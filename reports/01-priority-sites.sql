-- Priority sites: where to deep-scan next.
--
-- Scores only the findings that justify a deep scan (Critical x10, High x5):
--   * FullControlGrant counts only when granted directly to a user or guest.
--     Every site's default Owners group holds Full Control on the site root --
--     that is normal SharePoint, not a priority signal. A direct Full Control
--     grant to a person is.
--   * BrokenInheritance (Low) and DirectUserGrant (Medium) never count here.
--   * SharingLinkDetected counts at any severity; Medium links add one point.
--     Tier 1 can't see link scope, so the deep scan earns its keep enumerating
--     what's actually behind the link.
-- Sites already deep-scanned (Folder/File objects present) are excluded.
-- The full per-site picture is still in 11-site-findings-detail.
WITH Scored AS (
    SELECT
        sf.SiteId,
        sf.Severity,
        sf.FindingType,
        CASE
            WHEN sf.FindingType = 'FullControlGrant'
                 AND EXISTS (
                     SELECT 1 FROM Permissions pm
                     WHERE pm.ObjectId = sf.ObjectId
                       AND pm.PrincipalId = sf.PrincipalId
                       AND pm.PermissionLevel = 'Full Control'
                       AND pm.GrantedDirectly = 0
                 )
            THEN 0  -- group-held Full Control (e.g. default Owners group): normal
            WHEN sf.Severity IN ('Critical', 'High') THEN 1
            WHEN sf.FindingType = 'SharingLinkDetected' THEN 1
            ELSE 0
        END AS PriorityWorthy
    FROM SecurityFindings sf
)
SELECT
    s.Title AS Site,
    s.SiteUrl AS Url,
    SUM(CASE WHEN sc.Severity = 'Critical' AND sc.PriorityWorthy = 1 THEN 1 ELSE 0 END) AS Critical,
    SUM(CASE WHEN sc.Severity = 'High' AND sc.PriorityWorthy = 1 THEN 1 ELSE 0 END) AS High,
    SUM(CASE WHEN sc.FindingType = 'GuestDirectAccess' THEN 1 ELSE 0 END) AS GuestGrants,
    SUM(CASE WHEN sc.FindingType = 'SharingLinkDetected' THEN 1 ELSE 0 END) AS SharingLinks,
    SUM(CASE WHEN sc.FindingType = 'OrgWideExposure' THEN 1 ELSE 0 END) AS OrgWide,
    (SUM(CASE WHEN sc.Severity = 'Critical' AND sc.PriorityWorthy = 1 THEN 1 ELSE 0 END) * 10
     + SUM(CASE WHEN sc.Severity = 'High' AND sc.PriorityWorthy = 1 THEN 1 ELSE 0 END) * 5
     + SUM(CASE WHEN sc.FindingType = 'SharingLinkDetected' AND sc.Severity = 'Medium' AND sc.PriorityWorthy = 1 THEN 1 ELSE 0 END)
    ) AS Score
FROM Scored sc
JOIN Sites s ON s.SiteId = sc.SiteId
WHERE NOT EXISTS (
    SELECT 1 FROM Objects o
    WHERE o.SiteId = s.SiteId
      AND o.ObjectType IN ('Folder', 'File')
)
GROUP BY s.SiteId, s.Title, s.SiteUrl
HAVING Score > 0
ORDER BY Score DESC, Critical DESC, High DESC, s.Title;
