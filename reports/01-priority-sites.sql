-- Priority sites: every inventoried site ranked by finding severity.
-- Answers: "where do I deep-scan next?"
-- Usage: paste into the viewer query console, or
--   Invoke-SqliteQuery -DataSource SharePoint-Audit.db -Query (Get-Content reports/01-priority-sites.sql -Raw)
SELECT
    s.Title AS Site,
    s.SiteUrl AS Url,
    SUM(CASE WHEN sf.Severity = 'Critical' THEN 1 ELSE 0 END) AS Critical,
    SUM(CASE WHEN sf.Severity = 'High' THEN 1 ELSE 0 END) AS High,
    SUM(CASE WHEN sf.Severity = 'Medium' THEN 1 ELSE 0 END) AS Medium,
    SUM(CASE WHEN sf.Severity = 'Low' THEN 1 ELSE 0 END) AS Low,
    COUNT(*) AS Total
FROM SecurityFindings sf
JOIN Sites s ON s.SiteId = sf.SiteId
GROUP BY s.SiteId, s.Title, s.SiteUrl
ORDER BY Critical DESC, High DESC, Medium DESC, Low DESC, s.Title;
