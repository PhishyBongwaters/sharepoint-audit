-- Every grant held by a B2B guest principal (LoginName contains #ext#),
-- at site level and item level.
-- Answers: "where do external users have access?"
-- Uncomment the SiteUrl filter to scope to one site.
SELECT
    s.Title AS Site,
    o.ObjectType,
    o.ObjectTitle AS Object,
    o.ObjectUrl AS Url,
    p.Title AS Guest,
    p.LoginName,
    perms.PermissionLevel,
    CASE perms.GrantedDirectly WHEN 1 THEN 'direct' ELSE 'via group' END AS GrantType
FROM Permissions perms
JOIN Objects o ON o.ObjectId = perms.ObjectId
JOIN Principals p ON p.Id = perms.PrincipalId
JOIN Sites s ON s.SiteId = o.SiteId
WHERE p.LoginName LIKE '%#ext#%'
-- AND s.SiteUrl = 'https://tenant.sharepoint.com/sites/YourSite'
ORDER BY s.Title, o.ObjectUrl, p.Title;
