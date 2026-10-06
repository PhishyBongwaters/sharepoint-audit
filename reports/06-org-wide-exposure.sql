-- Grants to "Everyone except external users" / "Everyone".
-- High when the grant is Full Control/Contribute/Edit, Medium for read-only.
-- Often intentional -- triage, don't alarm.
-- Answers: "what is exposed org-wide?"
-- Uncomment the SiteUrl filter to scope to one site.
SELECT
    s.Title AS Site,
    o.ObjectType,
    o.ObjectTitle AS Object,
    o.ObjectUrl AS Url,
    p.Title AS Principal,
    perms.PermissionLevel,
    CASE WHEN perms.PermissionLevel IN ('Full Control', 'Contribute', 'Edit')
         THEN 'High' ELSE 'Medium' END AS ImpliedSeverity
FROM Permissions perms
JOIN Objects o ON o.ObjectId = perms.ObjectId
JOIN Principals p ON p.Id = perms.PrincipalId
JOIN Sites s ON s.SiteId = o.SiteId
WHERE (p.LoginName LIKE '%spo-grid-all-users%'
       OR p.Title IN ('Everyone except external users', 'Everyone'))
  AND perms.GrantedDirectly = 1
-- AND s.SiteUrl = 'https://tenant.sharepoint.com/sites/YourSite'
ORDER BY s.Title, o.ObjectUrl;
