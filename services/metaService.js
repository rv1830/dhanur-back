import axios from 'axios';
import moment from 'moment'; // तारीखों को हैंडल करने के लिए
import SocialAccount from '../models/SocialAccount.js';
import MetaAnalytics from '../models/MetaAnalytics.js'; // 👈 NEW: MetaAnalytics मॉडल इंपोर्ट करें

const META_BASE_URL = 'https://graph.facebook.com/v18.0';

// Utility function to get the date string for API calls
const getDateString = (daysAgo) => {
    return moment().subtract(daysAgo, 'days').format('YYYY-MM-DD');
};


/**
 * Unified function for Meta platforms (Instagram/Facebook).
 * 1. Exchanges short-lived code for a Long-Lived Access Token.
 * 2. Fetches the linked Instagram Business Account ID or Facebook Page ID.
 * @param {string} code - The authorization code from Meta.
 * @param {string} redirectUri - The redirect URI used.
 * @param {string} platform - 'instagram' or 'facebook'.
 */
export const getMetaLongLivedToken = async (code, redirectUri, platform) => {
    // 1. Exchange code for initial (short-lived) Access Token
    const initialTokenRes = await axios.get(`${META_BASE_URL}/oauth/access_token`, {
        params: {
            client_id: process.env.META_APP_ID,
            client_secret: process.env.META_APP_SECRET,
            redirect_uri: redirectUri,
            code: code,
        }
    });

    const shortLivedToken = initialTokenRes.data.access_token;

    // 2. Exchange short-lived token for long-lived token (60 days)
    const longLivedRes = await axios.get(`${META_BASE_URL}/oauth/access_token`, {
        params: {
            grant_type: 'fb_exchange_token',
            client_id: process.env.META_APP_ID,
            client_secret: process.env.META_APP_SECRET,
            fb_exchange_token: shortLivedToken
        }
    });

    let longLivedToken = longLivedRes.data.access_token;
    const expiresIn = longLivedRes.data.expires_in;

    let platformId;
    let profileName;

    if (platform === 'instagram') {
        // 3. Get the User Node and linked Instagram Business Account ID
        const userNodeRes = await axios.get(`${META_BASE_URL}/me`, {
            params: {
                fields: 'id,name,instagram_business_account', 
                access_token: longLivedToken
            }
        });

        const igBusinessAccount = userNodeRes.data.instagram_business_account;
        platformId = igBusinessAccount?.id;

        if (!platformId) {
            throw new Error("No Instagram Business Account linked to your Facebook Page.");
        }
        
        // Fetch Instagram Username (profileName) using the IG Business Account ID
        const igProfileRes = await axios.get(`${META_BASE_URL}/${platformId}`, {
             params: {
                fields: 'username',
                access_token: longLivedToken
            }
        });
        profileName = igProfileRes.data.username;

    } else if (platform === 'facebook') {
        // 3. Get the User's Pages and pick the first one (or implement selection logic)
        const pagesRes = await axios.get(`${META_BASE_URL}/me/accounts`, {
            params: {
                access_token: longLivedToken
            }
        });

        if (pagesRes.data.data.length === 0) {
            throw new Error("No Facebook Pages found.");
        }

        // Assuming first page for simplicity; in production, let user select
        platformId = pagesRes.data.data[0].id;
        profileName = pagesRes.data.data[0].name;

        // Update longLivedToken to page_access_token
        // NOTE: Page Token is usually needed for most Page/Insights calls
        const pageTokenRes = await axios.get(`${META_BASE_URL}/${platformId}`, {
            params: {
                fields: 'access_token',
                access_token: longLivedToken
            }
        });
        longLivedToken = pageTokenRes.data.access_token; // Use page-specific token
    }

    return { longLivedToken, expiresIn, platformId, profileName };
};


// Function to save the daily aggregated insights to MetaAnalytics model
const saveMetaInsights = async (socialAccount, dailyInsights, platformKey) => {
    const dataToSave = Object.entries(dailyInsights).map(([date, data]) => {
        let metrics = {};
        if (platformKey === 'INSTAGRAM') {
            metrics = {
                reach: data.reach || 0,
                impressions: data.impressions || 0,
                profileViews: data.profileViews || 0,
            };
        } else if (platformKey === 'FACEBOOK') {
            metrics = {
                pageImpressions: data.pageimpressions || 0,
                pageEngagedUsers: data.pagepostengagements || 0,
                pageViewsTotal: data.pageviewstotal || 0,
            };
        }
        
        return {
            date: moment(date).toDate(),
            ...metrics
        };
    });

    const bulkOps = dataToSave.map(data => ({
        updateOne: {
            filter: { socialAccountId: socialAccount._id, date: data.date },
            update: { 
                $set: { 
                    ...data, 
                    socialAccountId: socialAccount._id 
                } 
            },
            upsert: true,
        },
    }));

    await MetaAnalytics.bulkWrite(bulkOps);
    return bulkOps.length;
};


/**
 * Fetches and stores Instagram Insights (KPIs)
 */
export const fetchAndStoreInstagramInsights = async (socialAccount) => {
    const { accessToken, platformId: igUserId } = socialAccount;
    const daysToFetch = 30;
    const since = getDateString(daysToFetch);
    const until = getDateString(0); 
    const dailyInsights = {};

    // 1. Fetch Basic Profile Metrics (Followers, Name)
    const profileRes = await axios.get(`${META_BASE_URL}/${igUserId}`, {
        params: {
            fields: 'followers_count,username', 
            access_token: accessToken,
        }
    });
    
    // 2. Fetch Daily Insights 
    const metrics = 'reach,impressions,profile_views'; 
    const insightsRes = await axios.get(`${META_BASE_URL}/${igUserId}/insights`, {
        params: { 
            metric: metrics,
            period: 'day', // Daily aggregation
            since: since, 
            until: until,
            access_token: accessToken
        }
    });

    // 3. Process Daily Data
    insightsRes.data.data.forEach(metricData => {
        const metricName = metricData.name; 
        metricData.values.forEach(value => {
            const date = value.end_time.substring(0, 10); 
            dailyInsights[date] = dailyInsights[date] || {};
            // Key is the metric name without underscore
            dailyInsights[date][metricName.replace(/_/g, '')] = value.value; 
        });
    });

    // 4. Store/Upsert to MetaAnalytics DB
    const recordsSaved = await saveMetaInsights(socialAccount, dailyInsights, 'INSTAGRAM');

    // 5. Update SocialAccount with latest profile data
    await SocialAccount.updateOne(
        { _id: socialAccount._id },
        { 
            followersCount: profileRes.data.followers_count,
            profileName: profileRes.data.username,
            lastSynced: new Date(),
        }
    );

    return {
        followers: profileRes.data.followers_count,
        recordsSaved: recordsSaved,
    };
};

/**
 * Fetches and stores Facebook Insights (KPIs)
 */
export const fetchAndStoreFacebookInsights = async (socialAccount) => {
    const { accessToken, platformId: pageId } = socialAccount;
    const daysToFetch = 30;
    const since = getDateString(daysToFetch);
    const until = getDateString(0); 
    const dailyInsights = {};

    // 1. Fetch Basic Profile Metrics (Fan Count/Followers, Name)
    const profileRes = await axios.get(`${META_BASE_URL}/${pageId}`, {
        params: {
            fields: 'fan_count,name', 
            access_token: accessToken,
        }
    });
    
    // 2. Fetch Daily Insights 
    const metrics = 'page_impressions,page_post_engagements,page_views_total'; 
    const insightsRes = await axios.get(`${META_BASE_URL}/${pageId}/insights`, {
        params: { 
            metric: metrics,
            period: 'day', 
            since: since, 
            until: until,
            access_token: accessToken
        }
    });

    // 3. Process Daily Data
    insightsRes.data.data.forEach(metricData => {
        const metricName = metricData.name; 
        metricData.values.forEach(value => {
            const date = value.end_time.substring(0, 10); 
            dailyInsights[date] = dailyInsights[date] || {};
            // Key is the metric name without underscore
            dailyInsights[date][metricName.replace(/_/g, '')] = value.value; 
        });
    });

    // 4. Store/Upsert to MetaAnalytics DB
    const recordsSaved = await saveMetaInsights(socialAccount, dailyInsights, 'FACEBOOK');

    // 5. Update SocialAccount with latest profile data
    await SocialAccount.updateOne(
        { _id: socialAccount._id },
        { 
            followersCount: profileRes.data.fan_count,
            profileName: profileRes.data.name, 
            lastSynced: new Date(),
        }
    );

    return {
        followers: profileRes.data.fan_count,
        recordsSaved: recordsSaved,
    };
};


// =================================================================
// ⏰ NEW: CRON JOB LOGIC for ALL META ACCOUNTS 👈 NEW FUNCTION
// =================================================================

/**
 * पूरे सिस्टम में सभी कनेक्टेड Facebook और Instagram अकाउंट्स के लिए KPI फ़ेच और स्टोर करता है।
 * इसे डेली Cron Job द्वारा कॉल किया जाता है।
 */
export const runDailyMetaSync = async () => {
    console.log('[CRON JOB] Starting Daily Meta (FB/IG) Sync for ALL ACCOUNTS...');
    
    // 1. सभी कनेक्टेड Meta अकाउंट्स को DB से fetch करें
    const metaAccounts = await SocialAccount.find({ 
        platform: { $in: ['FACEBOOK', 'INSTAGRAM'] } 
    }).select('+refreshToken'); 

    if (metaAccounts.length === 0) {
        console.log('[CRON JOB] No Meta accounts found to sync. Exiting.');
        return { success: true, message: 'No accounts to sync.' };
    }

    let successCount = 0;
    let failureCount = 0;

    // 2. हर अकाउंट के लिए fetch और store फ़ंक्शन चलाएँ
    for (const account of metaAccounts) {
        try {
            console.log(`[CRON] Syncing ${account.platform}: ${account.profileName || account.platformId}`);
            
            if (account.platform === 'INSTAGRAM') {
                await fetchAndStoreInstagramInsights(account); 
            } else if (account.platform === 'FACEBOOK') {
                await fetchAndStoreFacebookInsights(account);
            }
            
            successCount++;
        } catch (error) {
            failureCount++;
            // Note: In real production, log error.message to a dedicated error tracker
            console.error(`[CRON] !!! FAILED to sync ${account.platform} ${account.platformId}: ${error.message}`);
        }
    }

    console.log(`[CRON JOB] Daily Meta Sync Finished. Success: ${successCount}, Failed: ${failureCount}`);
    return { success: true, successCount, failureCount };
};