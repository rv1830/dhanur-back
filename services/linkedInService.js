// services/linkedInService.js
import axios from 'axios';
import SocialAccount from '../models/SocialAccount.js';

/**
 * Exchanges code for Access Token and fetches LinkedIn Profile ID (2025 OpenID Connect).
 */
export const getLinkedInAccessToken = async (code, redirectUri) => {
    // 1. Exchange code for Access Token
    const tokenRes = await axios.post('https://www.linkedin.com/oauth/v2/accessToken', null, {
        params: {
            grant_type: 'authorization_code',
            code: code,
            redirect_uri: redirectUri,
            client_id: process.env.LINKEDIN_CLIENT_ID,
            client_secret: process.env.LINKEDIN_CLIENT_SECRET,
        },
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    });

    const accessToken = tokenRes.data.access_token;
    const expiresIn = tokenRes.data.expires_in || 5184000; // Default ~2 months

    // 2. Fetch User Info (new endpoint for OpenID Connect)
    const profileRes = await axios.get('https://api.linkedin.com/v2/userinfo', {
        headers: {
            Authorization: `Bearer ${accessToken}`
        }
    });

    const platformId = profileRes.data.sub; // This is the unique LinkedIn user ID

    return { longLivedToken: accessToken, expiresIn, platformId };
};

/**
 * Fetches and stores LinkedIn Insights — Connections count as approximate followers
 */
export const fetchAndStoreLinkedInInsights = async (socialAccount) => {
    const { accessToken } = socialAccount;

    // Note: Connections count API restricted — using approximate method or skip if not available
    // Current basic scopes se exact followers/connections nahi milta easily
    // MVP ke liye followersCount = 0 ya mock rakh sakte hain, ya remove kar

    // Example placeholder (real connections API partner program maangta hai)
    let followersCount = 0;

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