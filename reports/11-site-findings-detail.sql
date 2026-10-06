-- Every finding, severity-ordered. Scope to one site by uncommenting
-- the SiteUrl filter -- this is the per-site report you'd hand over.
SELECT
    sf.Severity,
    sf.FindingType,
    o.ObjectType,
    o.ObjectTitle AS Object,
    p.Title AS Principal,
    sf.PermissionLevel,
    sf.Details,
    sf.DetectedDate
FROM SecurityFindings sf
JOIN Sites s ON s.SiteId = sf.SiteId
LEFT JOIN Objects o ON o.ObjectId = sf.ObjectId
LEFT JOIN Principals p ON p.Id = sf.PrincipalId
-- WHERE s.SiteUrl = 'https://tenant.sharepoint.com/sites/YourSite'
ORDER BY
    CASE sf.Severity
        WHEN 'Critical' THEN 1
        WHEN 'High' THEN 2
        WHEN 'Medium' THEN 3
        ELSE 4 END,
    sf.FindingType,
    o.ObjectTitle;
