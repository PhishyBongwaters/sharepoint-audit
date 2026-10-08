-- Priority sites: where to deep-scan next.
--
-- Ranks on the findings that justify a deep scan, not on sprawl noise:
--   Critical x10, High x5. BrokenInheritance (Low) and DirectUserGrant
--   (Medium, noisy) don't count here. SharingLinkDetected counts at any
--   severity -- Tier 1 can't see link scope, so the deep scan earns its
--   keep enumerating what's actually behind the link.
-- Sites already deep-scanned (Folder/File objects present) are excluded.
-- The full per-site picture is still in 11-site-findings-detail.
SELECT
    s.Title AS Site,
    s.SiteUrl AS Url,
    SUM(CASE WHEN sf.Severity = 'Critical' THEN 1 ELSE 0 END) AS Critical,
    SUM(CASE WHEN sf.Severity = 'High' THEN 1 ELSE 0 END) AS High,
    SUM(CASE WHEN sf.FindingType = 'GuestDirectAccess' THEN 1 ELSE 0 END) AS GuestGrants,
    SUM(CASE WHEN sf.FindingType = 'SharingLinkDetected' THEN 1 ELSE 0 END) AS SharingLinks,
    SUM(CASE WHEN sf.FindingType = 'OrgWideExposure' THEN 1 ELSE 0 END) AS OrgWide,
    (SUM(CASE WHEN sf.Severity = 'Critical' THEN 1 ELSE 0 END) * 10
     + SUM(CASE WHEN sf.Severity = 'High' THEN 1 ELSE 0 END) * 5
     + SUM(CASE WHEN sf.FindingType = 'SharingLinkDetected' AND sf.Severity = 'Medium' THEN 1 ELSE 0 END)
    ) AS Score
FROM SecurityFindings sf
JOIN Sites s ON s.SiteId = sf.SiteId
WHERE (sf.Severity IN ('Critical', 'High')
       OR sf.FindingType = 'SharingLinkDetected')
  AND NOT EXISTS (
      SELECT 1 FROM Objects o
      WHERE o.SiteId = s.SiteId
        AND o.ObjectType IN ('Folder', 'File')
  )
GROUP BY s.SiteId, s.Title, s.SiteUrl
ORDER BY Score DESC, Critical DESC, High DESC, s.Title;
