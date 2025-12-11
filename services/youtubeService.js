// services/youtubeService.js

import axios from 'axios';
import moment from 'moment'; 
import SocialAccount from '../models/SocialAccount.js';
import YouTubeAnalytics from '../models/YouTubeAnalytics.js'; // Ensure this model exists and is imported

const YOUTUBE_BASE_URL = 'https://www.googleapis.com/youtube/v3';
const YOUTUBE_ANALYTICS_URL = 'https://youtubeanalytics.googleapis.com/v2';


// Utility function to get the current date minus a number of days in YYYY-MM-DD format
const getDateString = (daysAgo) => {
    return moment().subtract(daysAgo, 'days').format('YYYY-MM-DD');
};


/**
 * [DEBUG UTILITY] Simulates refreshing the access token using the stored refresh token.
 */
const refreshAccessToken = async (refreshToken) => {
    console.log('[DEBUG] Attempting to refresh access token...');
    try {
        const response = await axios.post('https://oauth2.googleapis.com/token', null, {
            params: {
                client_id: process.env.GOOGLE_CLIENT_ID,
                client_secret: process.env.GOOGLE_CLIENT_SECRET,
                refresh_token: refreshToken,
                grant_type: 'refresh_token',
            },
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });

        const newAccessToken = response.data.access_token;
        const expiresIn = response.data.expires_in;
        const newTokenExpires = moment().add(expiresIn, 'seconds').toDate();

        console.log('[DEBUG] Token refreshed successfully. New token expiry:', newTokenExpires);
        return { newAccessToken, newTokenExpires };

    } catch (error) {
        console.error('!!! CRITICAL ERROR: TOKEN REFRESH FAILED !!!', error.response?.data);
        throw new Error("Token refresh failed. User needs to re-authenticate.");
    }
};


/**
 * 1. Exchanges code for Access Token/Refresh Token.
 * 2. Fetches comprehensive Channel Profile Data using youtube.readonly.
 */
export const getYoutubeAuthData = async (code, redirectUri) => {
    console.log('[DEBUG] Starting getYoutubeAuthData (Token Exchange)');
    
    // 1. Exchange code for Access Token and Refresh Token
    try {
        const tokenRes = await axios.post('https://oauth2.googleapis.com/token', null, {
            params: {
                code: code,
                client_id: process.env.GOOGLE_CLIENT_ID,
                client_secret: process.env.GOOGLE_CLIENT_SECRET,
                redirect_uri: redirectUri,
                grant_type: 'authorization_code',
            },
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        const { access_token, refresh_token, expires_in } = tokenRes.data;
        console.log(`[DEBUG] Token Exchange Success. Refresh Token received: ${!!refresh_token}`);
        
        // 2. Fetch comprehensive Channel details (using all relevant parts)
        const channelRes = await axios.get(`${YOUTUBE_BASE_URL}/channels`, {
            params: {
                part: 'id,snippet,statistics,brandingSettings,contentDetails', 
                mine: true,
            },
            headers: {
                Authorization: `Bearer ${access_token}`
            }
        });

        if (channelRes.data.items.length === 0) {
            throw new Error("No YouTube channel found for the authenticated user.");
        }

        const channelItem = channelRes.data.items[0];
        const stats = channelItem.statistics;
        const snippet = channelItem.snippet;
        console.log(`[DEBUG] Channel Fetch Success. Channel ID: ${channelItem.id}, Subscribers: ${stats.subscriberCount}`);

        // 3. Package ALL profile data
        return { 
            accessToken: access_token, 
            refreshToken: refresh_token, 
            expiresIn: expires_in, 
            
            platformId: channelItem.id, 
            profileName: snippet.title,
            followersCount: parseInt(stats.subscriberCount, 10) || 0,
            profilePictureUrl: snippet.thumbnails.high.url,
            channelDescription: snippet.description,
            totalVideos: parseInt(stats.videoCount, 10) || 0,
            totalViews: parseInt(stats.viewCount, 10) || 0,
        };
    } catch (error) {
        console.error('!!! ERROR DURING AUTH/CHANNEL FETCH !!!', error.response?.data || error.message);
        throw new Error("Failed during YouTube authentication or channel fetch.");
    }
};

/**
 * Fetches time-series KPI data using the YouTube Analytics API and stores it in YouTubeAnalytics model.
 * FIX: Uses the correct metric name and removes the failing monetary API call.
 */
export const fetchAndStoreYoutubeKPIs = async (socialAccount) => {
    console.log(`[DEBUG] Starting fetchAndStoreYoutubeKPIs for Channel: ${socialAccount.platformId}`);
    
    let accessToken = socialAccount.accessToken;
    const channelId = socialAccount.platformId;

    // --- Token Refresh Check (CRITICAL) ---
    if (moment(socialAccount.tokenExpires).isBefore(moment())) {
        console.log('[DEBUG] Access token is expired. Attempting refresh...');
        if (!socialAccount.refreshToken) {
             throw new Error("Token expired and no Refresh Token available. Re-auth required.");
        }
        const { newAccessToken, newTokenExpires } = await refreshAccessToken(socialAccount.refreshToken);
        accessToken = newAccessToken;

        // Update DB with new token details
        await SocialAccount.updateOne(
            { _id: socialAccount._id },
            { $set: { accessToken: newAccessToken, tokenExpires: newTokenExpires } }
        );
        console.log('[DEBUG] DB updated with new Access Token.');
    }


    const daysToFetch = 30; 
    const startDate = getDateString(daysToFetch);
    const endDate = getDateString(0); 
    
    const results = {}; 

    // === API CALL 1: NON-MONETARY METRICS (FIXED METRIC NAMES) ===
    // FIX 1: 'watchTimeMinutes' changed to correct 'estimatedMinutesWatched'
    // FIX 2: Added engagement metrics (comments, likes, shares) back, assuming they work with 'day'
    const nonMonetaryMetrics = 'views,estimatedMinutesWatched,subscribersGained,comments,likes,shares'; 
    try {
        console.log(`[DEBUG] API 1: Fetching STABLE metrics (${nonMonetaryMetrics}) from ${startDate} to ${endDate}`);
        
        const nonMonetaryRes = await axios.get(`${YOUTUBE_ANALYTICS_URL}/reports`, {
            params: {
                ids: `channel==${channelId}`,
                startDate: startDate,
                endDate: endDate,
                metrics: nonMonetaryMetrics,
                dimensions: 'day',
                sort: 'day', 
            },
            headers: { Authorization: `Bearer ${accessToken}` }
        });

        console.log(`[DEBUG] API 1 Success. Rows received: ${nonMonetaryRes.data.rows.length}`);
        
        // Map results into the results object using the date as the key
        nonMonetaryRes.data.rows.forEach(row => {
            // Order must match the 'nonMonetaryMetrics' list
            const [date, views, watchTime, subsGained, comments, likes, shares] = row;
            results[date] = {
                date: moment(date).toDate(),
                views, comments, likes, shares,
                subscribersGained: subsGained,
                watchTimeMinutes: watchTime, // Variable name in DB model
                
                // Monetary data is explicitly set to 0 as the scope and API call are removed
                estimatedRevenue: 0, 
                adImpressions: 0,    
            };
        });
    } catch (error) {
        console.error('!!! API 1 FAILED (Core Metrics) !!! Check permissions/metrics/dates.');
        console.error('API Error Details:', error.response?.data || error.message);
        throw new Error("Failed to fetch YouTube Core Engagement KPIs."); 
    }


    // === API CALL 2: MONETARY METRICS (REMOVED) ===
    // This call is now REMOVED as per your request to remove monetary scopes.
    
    // --- DB Transaction: Store Merged Data ---
    const dataToSave = Object.values(results);
    console.log(`[DEBUG] Preparing to save ${dataToSave.length} KPI records to YouTubeAnalytics table.`);

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

    await YouTubeAnalytics.bulkWrite(bulkOps);

    // Update the SocialAccount lastSynced time
    await SocialAccount.updateOne(
        { _id: socialAccount._id },
        { $set: { lastSynced: new Date() } }
    );
    
    console.log('[DEBUG] KPI Bulk Write and SocialAccount sync successful.');
    return { recordsSaved: bulkOps.length };
};


/**
 * Fetches and stores only the latest comprehensive YouTube Profile (for manual sync).
 */
export const fetchAndStoreYoutubeProfile = async (socialAccount) => {
    // NOTE: In a real system, you must run token refresh check before this call!
    const currentAccessToken = socialAccount.accessToken;
    const channelId = socialAccount.platformId;
    console.log('[DEBUG] Starting fetchAndStoreYoutubeProfile (Refresh basic stats).');

    try {
        const profileRes = await axios.get(`${YOUTUBE_BASE_URL}/channels`, {
            params: {
                part: 'snippet,statistics',
                id: channelId,
            },
            headers: {
                Authorization: `Bearer ${currentAccessToken}`
            }
        });

        const channelData = profileRes.data.items[0];
        const stats = channelData?.statistics;
        const snippet = channelData?.snippet;

        const profileUpdates = {
            profileName: snippet.title,
            followersCount: stats ? parseInt(stats.subscriberCount, 10) : 0,
            profilePictureUrl: snippet.thumbnails.high.url,
            channelDescription: snippet.description,
            totalVideos: stats ? parseInt(stats.videoCount, 10) : 0,
            totalViews: stats ? parseInt(stats.viewCount, 10) : 0,
            lastSynced: new Date(),
        };

        await SocialAccount.updateOne(
            { _id: socialAccount._id },
            { $set: profileUpdates }
        );
        console.log('[DEBUG] Profile stats updated successfully.');
        return profileUpdates;
        
    } catch (error) {
        console.error('!!! ERROR during Profile Stats Refresh !!!', error.response?.data || error.message);
        throw new Error("Failed to refresh YouTube profile stats.");
    }
};