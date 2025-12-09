// services/metaService.js
import axios from 'axios';
import SocialAccount from '../models/SocialAccount.js';

const META_BASE_URL = 'https://graph.facebook.com/v18.0';

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

    const longLivedToken = longLivedRes.data.access_token;
    const expiresIn = longLivedRes.data.expires_in;

    let platformId;

    if (platform === 'instagram') {
        // 3. Get the User Node and linked Instagram Business Account ID
        const userNodeRes = await axios.get(`${META_BASE_URL}/me`, {
            params: {
                fields: 'id,name,instagram_business_account', 
                access_token: longLivedToken
            }
        });

        platformId = userNodeRes.data.instagram_business_account?.id;

        if (!platformId) {
            throw new Error("No Instagram Business Account linked to your Facebook Page.");
        }
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
        // Update longLivedToken to page_access_token if needed
        const pageTokenRes = await axios.get(`${META_BASE_URL}/${platformId}`, {
            params: {
                fields: 'access_token',
                access_token: longLivedToken
            }
        });
        longLivedToken = pageTokenRes.data.access_token; // Use page-specific token
    }

    return { longLivedToken, expiresIn, platformId };
};

/**
 * Fetches and stores Instagram Insights (KPIs)
 */
export const fetchAndStoreInstagramInsights = async (socialAccount) => {
    const { accessToken, platformId: igUserId } = socialAccount;

    // 1. Fetch Basic Metrics (Followers)
    const profileRes = await axios.get(`${META_BASE_URL}/${igUserId}`, {
        params: {
            fields: 'followers_count,media_count',
            access_token: accessToken,
        }
    });
    
    // 2. Fetch Aggregated Insights (e.g., Reach, Impressions for past 30 days)
    const insightsRes = await axios.get(`${META_BASE_URL}/${igUserId}/insights`, {
        params: { 
            metric: 'reach,impressions,profile_views',
            period: 'days_28', // Corrected to days_28 as per API
            access_token: accessToken
        }
    });

    // --- MongoDB Update ---
    await SocialAccount.updateOne(
        { _id: socialAccount._id },
        { 
            followersCount: profileRes.data.followers_count,
            lastSynced: new Date(),
            // Future: Save insightsRes.data to PerformanceMetric collection
        }
    );

    return {
        followers: profileRes.data.followers_count,
        insights: insightsRes.data,
    };
};

/**
 * Fetches and stores Facebook Insights (KPIs)
 */
export const fetchAndStoreFacebookInsights = async (socialAccount) => {
    const { accessToken, platformId: pageId } = socialAccount;

    // 1. Fetch Basic Metrics (Fans/Followers)
    const profileRes = await axios.get(`${META_BASE_URL}/${pageId}`, {
        params: {
            fields: 'fan_count,new_like_count',
            access_token: accessToken,
        }
    });
    
    // 2. Fetch Aggregated Insights (e.g., Reach, Impressions for past 28 days)
    const insightsRes = await axios.get(`${META_BASE_URL}/${pageId}/insights`, {
        params: { 
            metric: 'page_impressions,page_engaged_users,page_views',
            period: 'days_28',
            access_token: accessToken
        }
    });

    // --- MongoDB Update ---
    await SocialAccount.updateOne(
        { _id: socialAccount._id },
        { 
            followersCount: profileRes.data.fan_count,
            lastSynced: new Date(),
            // Future: Save insightsRes.data to PerformanceMetric collection
        }
    );

    return {
        followers: profileRes.data.fan_count,
        insights: insightsRes.data,
    };
};