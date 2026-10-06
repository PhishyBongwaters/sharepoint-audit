-- Sharing-link inventory from the hidden backing groups SharePoint
-- creates per link (Tier 1). The type hint is NOT authoritative --
-- verify the actual link scope in SharePoint before reporting it.
-- Answers: "where are sharing links in play?"
-- Uncomment the SiteUrl filter to scope to one site.
SELECT
    s.Title AS Site,
    s.SiteUrl AS SiteUrl,
    sl.GroupTitle AS BackingGroup,
    sl.FileGuid,
    COALESCE(NULLIF(sl.TypeHint, ''), 'unknown') AS TypeHint,
    CASE WHEN sl.TypeHint LIKE '%Anonymous%' THEN 'Critical'
         WHEN sl.TypeHint LIKE '%Organization%' THEN 'High'
         ELSE 'Medium' END AS ImpliedSeverity
FROM SharingLinks sl
JOIN Sites s ON s.SiteId = sl.SiteId
-- WHERE s.SiteUrl = 'https://tenant.sharepoint.com/sites/YourSite'
ORDER BY
    CASE WHEN sl.TypeHint LIKE '%Anonymous%' THEN 1
         WHEN sl.TypeHint LIKE '%Organization%' THEN 2
         ELSE 3 END,
    s.Title;
