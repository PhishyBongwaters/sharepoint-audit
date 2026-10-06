-- High findings on individual folders/files (deep-scan results).
-- A High here means something specific -- a named grant on one object --
-- unlike site-level Highs, which are often just site owners.
-- Answers: "what did the deep scan actually find?"
-- Uncomment the SiteUrl filter to scope to one site.
SELECT
    s.Title AS Site,
    o.ObjectType,
    o.ObjectTitle AS Object,
    o.ObjectUrl AS Url,
    sf.FindingType,
    p.Title AS Principal,
    sf.PermissionLevel,
    sf.Details
FROM SecurityFindings sf
JOIN Sites s ON s.SiteId = sf.SiteId
JOIN Objects o ON o.ObjectId = sf.ObjectId
LEFT JOIN Principals p ON p.Id = sf.PrincipalId
WHERE sf.Severity = 'High'
  AND o.ObjectType IN ('Folder', 'File')
-- AND s.SiteUrl = 'https://tenant.sharepoint.com/sites/YourSite'
ORDER BY s.Title, o.ObjectUrl;
