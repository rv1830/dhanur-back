// --- services/facebookService.js (NEW) ---
import axios from 'axios';
import moment from 'moment';
import SocialAccount from '../models/SocialAccount.js';
import FacebookAnalytics from '../models/FacebookAnalytics.js'; 

const META_BASE_URL = 'https://graph.facebook.com/v18.0';

const getDateString = (daysAgo) => {
    return moment().subtract(daysAgo, 'days').format('YYYY-MM-DD');
};

/**
 * Handles the token exchange and fetching of Facebook Page details.
 */
export const getFacebookAuthData = async (code, redirectUri, longLivedToken) => {
    // 1. Get the User's Pages and pick the first one (assuming the user wants to connect this page)
    const pagesRes = await axios.get(`${META_BASE_URL}/me/accounts`, {
        params: {
            access_token: longLivedToken
        }
    });

    if (pagesRes.data.data.length === 0) {
        throw new Error("No Facebook Pages found.");
    }

    // Use the first page for connection
    const pageData = pagesRes.data.data[0];
    const platformId = pageData.id;
    const profileName = pageData.name;
    let pageAccessToken = pageData.access_token; // This is the Page Token

    // 2. Fetch Fan Count
    const profileRes = await axios.get(`${META_BASE_URL}/${platformId}`, {
        params: {
            fields: 'fan_count,picture', 
            access_token: pageAccessToken
        }
    });
    
    return { 
        longLivedToken: pageAccessToken, // Use Page Token for future calls
        platformId: platformId, 
        profileName: profileName,
        followersCount: profileRes.data.fan_count,
        profilePictureUrl: profileRes.data.picture?.data?.url,
    };
};

// Function to save daily aggregated insights
const saveFacebookInsights = async (socialAccount, dailyInsights) => {
    const dataToSave = Object.entries(dailyInsights).map(([date, data]) => ({
        date: moment(date).toDate(),
        pageImpressions: data.pageimpressions || 0,
        pageEngagedUsers: data.pagepostengagements || 0,
        pageViewsTotal: data.pageviewstotal || 0,
        pageFanCount: data.pagefancount || 0,
    }));

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

    await FacebookAnalytics.bulkWrite(bulkOps);
    return bulkOps.length;
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

    // 1. Fetch Basic Profile Metrics (Fan Count/Followers)
    const profileRes = await axios.get(`${META_BASE_URL}/${pageId}`, {
        params: {
            fields: 'fan_count,name,picture', 
            access_token: accessToken,
        }
    });
    
    // 2. Fetch Daily Insights 
    // page_fan_adds_unique can also be used for daily fan count
    const metrics = 'page_impressions,page_post_engagements,page_views_total,page_fan_count'; 
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

    // 4. Store/Upsert to FacebookAnalytics DB
    const recordsSaved = await saveFacebookInsights(socialAccount, dailyInsights);

    // 5. Update SocialAccount with latest profile data
    await SocialAccount.updateOne(
        { _id: socialAccount._id },
        { 
            followersCount: profileRes.data.fan_count,
            profileName: profileRes.data.name, 
            profilePictureUrl: profileRes.data.picture?.data?.url,
            lastSynced: new Date(),
        }
    );

    return {
        followers: profileRes.data.fan_count,
        recordsSaved: recordsSaved,
    };
};

/**
 * Runs daily sync for all connected Facebook accounts.
 */
export const runDailyFacebookSync = async () => {
    console.log('[CRON JOB] Starting Daily Facebook Sync...');
    const facebookAccounts = await SocialAccount.find({ platform: 'FACEBOOK' }); 

    let successCount = 0;
    let failureCount = 0;

    for (const account of facebookAccounts) {
        try {
            console.log(`[CRON] Syncing FACEBOOK: ${account.profileName}`);
            await fetchAndStoreFacebookInsights(account); 
            successCount++;
        } catch (error) {
            failureCount++;
            console.error(`[CRON] !!! FAILED to sync Facebook ${account.platformId}: ${error.message}`);
        }
    }

    return { success: true, successCount, failureCount };
};