// services/youtubeService.js
import axios from 'axios';
import SocialAccount from '../models/SocialAccount.js';

const YOUTUBE_BASE_URL = 'https://www.googleapis.com/youtube/v3';

/**
 * Exchanges code for Access Token and fetches YouTube Channel ID.
 */
export const getYoutubeAccessToken = async (code, redirectUri) => {
    // 1. Exchange code for Access Token
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

    const accessToken = tokenRes.data.access_token;
    const expiresIn = tokenRes.data.expires_in;

    // 2. Fetch Channel ID (using 'mine=true' requires the correct scope)
    const channelRes = await axios.get(`${YOUTUBE_BASE_URL}/channels`, {
        params: {
            part: 'id',
            mine: true,
        },
        headers: {
            Authorization: `Bearer ${accessToken}`
        }
    });

    if (channelRes.data.items.length === 0) {
        throw new Error("No YouTube channel found for the authenticated user.");
    }

    const platformId = channelRes.data.items[0].id; // YouTube Channel ID

    // Note: Google tokens don't have a direct 'long-lived' exchange, but use Refresh Tokens for permanent access. 
    // This example uses the initial access token.
    return { longLivedToken: accessToken, expiresIn, platformId };
};

/**
 * Fetches and stores YouTube Insights (Subscriber Count).
 */
export const fetchAndStoreYoutubeInsights = async (socialAccount) => {
    const { accessToken, platformId: channelId } = socialAccount;

    // 1. Fetch Subscriber Count
    const statsRes = await axios.get(`${YOUTUBE_BASE_URL}/channels`, {
        params: {
            part: 'statistics',
            id: channelId,
        },
        headers: {
            Authorization: `Bearer ${accessToken}`
        }
    });

    const stats = statsRes.data.items[0]?.statistics;
    const followersCount = stats ? parseInt(stats.subscriberCount, 10) : 0;

    // --- MongoDB Update ---
    await SocialAccount.updateOne(
        { _id: socialAccount._id },
        { 
            followersCount,
            lastSynced: new Date(),
        }
    );

    return {
        followers: followersCount,
    };
};