// --- services/instagramService.js (NEW) ---
import axios from 'axios';
import moment from 'moment';
import SocialAccount from '../models/SocialAccount.js';
import InstagramAnalytics from '../models/InstagramAnalytics.js'; 

const META_BASE_URL = 'https://graph.facebook.com/v18.0';

const getDateString = (daysAgo) => {
    return moment().subtract(daysAgo, 'days').format('YYYY-MM-DD');
};

/**
 * Exchanges short-lived code for a Long-Lived Access Token, and fetches IG Business Account ID.
 */
export const getInstagramAuthData = async (code, redirectUri, longLivedToken) => {
    // 1. Get the User Node and linked Instagram Business Account ID
    const userNodeRes = await axios.get(`${META_BASE_URL}/me`, {
        params: {
            fields: 'id,name,instagram_business_account', 
            access_token: longLivedToken
        }
    });

    const igBusinessAccount = userNodeRes.data.instagram_business_account;
    const platformId = igBusinessAccount?.id;

    if (!platformId) {
        throw new Error("No Instagram Business Account linked to your Facebook Page.");
    }
    
    // 2. Fetch Instagram Username, Followers and Profile Picture
    const igProfileRes = await axios.get(`${META_BASE_URL}/${platformId}`, {
        params: {
            fields: 'username,followers_count,profile_picture_url',
            access_token: longLivedToken
        }
    });
    
    return { 
        longLivedToken, // Use the long-lived user token for IG calls
        platformId: platformId, 
        profileName: igProfileRes.data.username,
        followersCount: igProfileRes.data.followers_count,
        profilePictureUrl: igProfileRes.data.profile_picture_url,
    };
};


// Function to save the daily aggregated insights to InstagramAnalytics model
const saveInstagramInsights = async (socialAccount, dailyInsights) => {
    const dataToSave = Object.entries(dailyInsights).map(([date, data]) => ({
        date: moment(date).toDate(),
        reach: data.reach || 0,
        impressions: data.impressions || 0,
        profileViews: data.profileviews || 0,
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

    await InstagramAnalytics.bulkWrite(bulkOps);
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

    // 1. Fetch Basic Profile Metrics (Followers, Name, Picture)
    const profileRes = await axios.get(`${META_BASE_URL}/${igUserId}`, {
        params: {
            fields: 'followers_count,username,profile_picture_url', 
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

    // 4. Store/Upsert to InstagramAnalytics DB
    const recordsSaved = await saveInstagramInsights(socialAccount, dailyInsights);

    // 5. Update SocialAccount with latest profile data
    await SocialAccount.updateOne(
        { _id: socialAccount._id },
        { 
            followersCount: profileRes.data.followers_count,
            profileName: profileRes.data.username,
            profilePictureUrl: profileRes.data.profile_picture_url,
            lastSynced: new Date(),
        }
    );

    return {
        followers: profileRes.data.followers_count,
        recordsSaved: recordsSaved,
    };
};

/**
 * Runs daily sync for all connected Instagram accounts.
 */
export const runDailyInstagramSync = async () => {
    console.log('[CRON JOB] Starting Daily Instagram Sync...');
    const instagramAccounts = await SocialAccount.find({ platform: 'INSTAGRAM' }); 

    let successCount = 0;
    let failureCount = 0;

    for (const account of instagramAccounts) {
        try {
            console.log(`[CRON] Syncing INSTAGRAM: ${account.profileName}`);
            await fetchAndStoreInstagramInsights(account); 
            successCount++;
        } catch (error) {
            failureCount++;
            console.error(`[CRON] !!! FAILED to sync Instagram ${account.platformId}: ${error.message}`);
        }
    }

    return { success: true, successCount, failureCount };
};