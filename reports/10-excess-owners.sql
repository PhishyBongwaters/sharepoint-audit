-- Objects where 4 or more distinct principals hold Full Control.
-- Answers: "where are there too many owners?"
-- Uncomment the SiteUrl filter to scope to one site.
SELECT
    s.Title AS Site,
    o.ObjectType,
    o.ObjectTitle AS Object,
    o.ObjectUrl AS Url,
    COUNT(DISTINCT p.Id) AS FullControlHolders,
    GROUP_CONCAT(p.Title, '; ') AS Holders
FROM Permissions perms
JOIN Objects o ON o.ObjectId = perms.ObjectId
JOIN Principals p ON p.Id = perms.PrincipalId
JOIN Sites s ON s.SiteId = o.SiteId
WHERE perms.PermissionLevel = 'Full Control'
-- AND s.SiteUrl = 'https://tenant.sharepoint.com/sites/YourSite'
GROUP BY s.SiteId, s.Title, o.ObjectId, o.ObjectType, o.ObjectTitle, o.ObjectUrl
HAVING COUNT(DISTINCT p.Id) > 3
ORDER BY FullControlHolders DESC, s.Title;
