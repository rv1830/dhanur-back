// services/snapchatService.js
import axios from 'axios';
import SocialAccount from '../models/SocialAccount.js';

const SNAPCHAT_BASE_URL = 'https://api.snapchat.com';

/**
 * Exchanges code for Access Token and fetches Snapchat User ID.
 */
export const getSnapchatAccessToken = async (code, redirectUri) => {
    // 1. Exchange code for Access Token
    const tokenRes = await axios.post('https://accounts.snapchat.com/login/oauth2/access_token', null, {
        params: {
            grant_type: 'authorization_code',
            code: code,
            redirect_uri: redirectUri,
            client_id: process.env.SNAPCHAT_CLIENT_ID,
            client_secret: process.env.SNAPCHAT_CLIENT_SECRET,
        },
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    });

    const accessToken = tokenRes.data.access_token;
    const expiresIn = tokenRes.data.expires_in;

    // 2. Fetch User Info/ID
    const profileRes = await axios.get(`${SNAPCHAT_BASE_URL}/v1/me`, {
        headers: {
            Authorization: `Bearer ${accessToken}`
        }
    });

    const platformId = profileRes.data.id; // Unique Snap User ID

    return { longLivedToken: accessToken, expiresIn, platformId };
};

/**
 * Fetches and stores Snapchat Insights (Subscribers/Followers)
 * Note: Real subscriber count often requires advanced API access. Using a placeholder or simple public metric if available.
 */
export const fetchAndStoreSnapchatInsights = async (socialAccount) => {
    const { accessToken } = socialAccount;

    // Placeholder: The actual API call for follower count is complex and requires specific scopes/access.
    // For MVP, we'll mock the count or use a basic endpoint if available.
    let followersCount = Math.floor(Math.random() * 50000) + 10000; // Mock followers

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