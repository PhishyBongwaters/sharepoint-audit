-- Objects with unique (broken) permissions, rolled up per site.
-- The sprawl signal: the more unique-permission objects, the harder the
-- site is to reason about. ItemLevel counts folders/files (deep scan);
-- ListLevel counts libraries/lists (Tier 1).
-- Answers: "where is inheritance broken all over the place?"
SELECT
    s.Title AS Site,
    s.SiteUrl AS SiteUrl,
    SUM(CASE WHEN o.ObjectType IN ('Folder', 'File') THEN 1 ELSE 0 END) AS ItemLevel,
    SUM(CASE WHEN o.ObjectType IN ('Library', 'List') THEN 1 ELSE 0 END) AS ListLevel,
    COUNT(*) AS Total
FROM Objects o
JOIN Sites s ON s.SiteId = o.SiteId
WHERE o.HasUniquePermissions = 1
GROUP BY s.SiteId, s.Title, s.SiteUrl
ORDER BY Total DESC;
