// services/twitterService.js
import axios from 'axios';
import SocialAccount from '../models/SocialAccount.js';

const TWITTER_BASE_URL = 'https://api.twitter.com/2';

/**
 * Exchanges code for Access Token and fetches Twitter User ID.
 * NOTE: Twitter API v2 uses a three-legged OAuth 2.0 flow. 
 * This requires a Client ID, Client Secret, and PKCE (Code Verifier/Challenge) flow.
 * For simplicity and fitting the current `handleCallback` signature, this assumes the final step 
 * after the user returns with the code.
 */
export const getTwitterAccessToken = async (code, redirectUri) => {
    // 1. Exchange code for Access Token
    const tokenRes = await axios.post('https://api.twitter.com/2/oauth2/token', null, {
        params: {
            code: code,
            grant_type: 'authorization_code',
            client_id: process.env.TWITTER_CLIENT_ID,
            // PKCE is required; you'll need to pass the code_verifier from your frontend
            // code_verifier: 'YOUR_CODE_VERIFIER', 
            redirect_uri: redirectUri,
        },
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            // Basic Auth with Client ID and Secret may be needed depending on app config
            // Authorization: `Basic ${Buffer.from(`${process.env.TWITTER_CLIENT_ID}:${process.env.TWITTER_CLIENT_SECRET}`).toString('base64')}`
        }
    });

    const accessToken = tokenRes.data.access_token;
    const expiresIn = tokenRes.data.expires_in;

    // 2. Fetch User Info/ID
    const profileRes = await axios.get(`${TWITTER_BASE_URL}/users/me`, {
        headers: {
            Authorization: `Bearer ${accessToken}`
        }
    });

    const platformId = profileRes.data.data.id; // Unique Twitter User ID

    return { longLivedToken: accessToken, expiresIn, platformId };
};

/**
 * Fetches and stores Twitter Insights (Follower Count).
 */
export const fetchAndStoreTwitterInsights = async (socialAccount) => {
    const { accessToken, platformId: userId } = socialAccount;

    // 1. Fetch Follower Count
    const statsRes = await axios.get(`${TWITTER_BASE_URL}/users/${userId}`, {
        params: {
            'user.fields': 'public_metrics',
        },
        headers: {
            Authorization: `Bearer ${accessToken}`
        }
    });

    const followersCount = statsRes.data.data.public_metrics.followers_count;

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