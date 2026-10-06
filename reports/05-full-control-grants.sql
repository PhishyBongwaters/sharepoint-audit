-- Who holds Full Control, and where. Site Admins are flagged.
-- Answers: "who can do anything, anywhere?"
-- Uncomment the SiteUrl filter to scope to one site.
SELECT
    s.Title AS Site,
    o.ObjectType,
    o.ObjectTitle AS Object,
    o.ObjectUrl AS Url,
    p.Title AS Principal,
    p.PrincipalTypeName AS PrincipalType,
    p.IsSiteAdmin AS SiteAdmin,
    CASE perms.GrantedDirectly WHEN 1 THEN 'direct' ELSE 'via group' END AS GrantType
FROM Permissions perms
JOIN Objects o ON o.ObjectId = perms.ObjectId
JOIN Principals p ON p.Id = perms.PrincipalId
JOIN Sites s ON s.SiteId = o.SiteId
WHERE perms.PermissionLevel = 'Full Control'
-- AND s.SiteUrl = 'https://tenant.sharepoint.com/sites/YourSite'
ORDER BY s.Title, o.ObjectUrl, p.Title;
