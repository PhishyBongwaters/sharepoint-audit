-- Every Critical finding, with site and object context.
-- Answers: "what needs attention right now?"
-- Uncomment the SiteUrl filter to scope to one site.
SELECT
    s.Title AS Site,
    s.SiteUrl AS SiteUrl,
    o.ObjectType,
    o.ObjectTitle AS Object,
    o.ObjectUrl AS Url,
    sf.FindingType,
    sf.Details
FROM SecurityFindings sf
JOIN Sites s ON s.SiteId = sf.SiteId
LEFT JOIN Objects o ON o.ObjectId = sf.ObjectId
WHERE sf.Severity = 'Critical'
-- AND s.SiteUrl = 'https://tenant.sharepoint.com/sites/YourSite'
ORDER BY s.Title, o.ObjectType, o.ObjectTitle;
