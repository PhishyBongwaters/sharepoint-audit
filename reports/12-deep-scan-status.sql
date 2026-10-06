-- Deep-scan progress: which lists/libraries are done, in progress,
-- or not started for each deep-scanned site.
-- Answers: "did the deep scan finish, and where did it stop?"
-- Uncomment the SiteUrl filter to scope to one site.
SELECT
    s.Title AS Site,
    s.SiteUrl AS SiteUrl,
    o.ObjectTitle AS List,
    dp.Status,
    dp.ItemsSeen,
    dp.UpdatedAt
FROM DeepScanProgress dp
JOIN Sites s ON s.SiteId = dp.SiteId
JOIN Objects o ON o.ObjectId = dp.ListObjectId
-- WHERE s.SiteUrl = 'https://tenant.sharepoint.com/sites/YourSite'
ORDER BY s.Title, o.ObjectTitle;
