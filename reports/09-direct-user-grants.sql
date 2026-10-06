-- Direct grants to named (non-guest) users: people given access
-- individually instead of through groups. Review debt -- noisy by nature,
-- triage, don't alarm.
-- Answers: "who was granted access one-off?"
-- Uncomment the SiteUrl filter to scope to one site.
SELECT
    s.Title AS Site,
    o.ObjectType,
    o.ObjectTitle AS Object,
    o.ObjectUrl AS Url,
    p.Title AS User,
    p.UserPrincipalName AS UPN,
    perms.PermissionLevel
FROM Permissions perms
JOIN Objects o ON o.ObjectId = perms.ObjectId
JOIN Principals p ON p.Id = perms.PrincipalId
JOIN Sites s ON s.SiteId = o.SiteId
WHERE p.PrincipalTypeName = 'User'
  AND p.LoginName NOT LIKE '%#ext#%'
  AND perms.GrantedDirectly = 1
-- AND s.SiteUrl = 'https://tenant.sharepoint.com/sites/YourSite'
ORDER BY s.Title, o.ObjectUrl, p.Title;
