// services/twitterService.js
import axios from 'axios';
import SocialAccount from '../models/SocialAccount.js';

const TWITTER_BASE_URL = 'https://api.twitter.com/2';
const TWITTER_TOKEN_ENDPOINT = 'https://api.twitter.com/2/oauth2/token';
const TWITTER_USER_ENDPOINT = 'https://api.twitter.com/2/users/me';

/**
 * Exchanges code for Access Token and fetches Twitter User ID.
 * NOTE: This function MUST be called with codeVerifier from the frontend/query.
 */
export const getTwitterAccessToken = async (code, redirectUri, codeVerifier) => {
    
    // 1. Build Authentication Header (Basic Auth: Client ID + Secret)
    // Twitter requires this for the token endpoint
    const encodedCredentials = Buffer.from(
        `${process.env.TWITTER_CLIENT_ID}:${process.env.TWITTER_CLIENT_SECRET}`
    ).toString('base64');

    // 2. Build the POST body for token exchange
    const tokenParams = new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: redirectUri,
        // 🛑 CRITICAL FIX: PKCE Code Verifier is mandatory
        code_verifier: codeVerifier, 
    });

    try {
        const tokenRes = await axios.post(TWITTER_TOKEN_ENDPOINT, tokenParams, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                // 🛑 CRITICAL FIX: Use Basic Auth header
                'Authorization': `Basic ${encodedCredentials}`,
            }
        });

        const accessToken = tokenRes.data.access_token;
        const refreshToken = tokenRes.data.refresh_token; // Save this!
        const expiresIn = tokenRes.data.expires_in;

        // 3. Fetch User Info/ID (Public Metrics is needed for follower count)
        const profileRes = await axios.get(TWITTER_USER_ENDPOINT, {
            headers: {
                Authorization: `Bearer ${accessToken}`
            },
            // Zaroori parameter: fields is required to get public_metrics (followers count)
            params: {
                'user.fields': 'public_metrics,profile_image_url,name' 
            }
        });
        
        const userData = profileRes.data.data;

        const platformId = userData.id; 
        const profileName = userData.name;
        const followersCount = userData.public_metrics.followers_count;

        return { 
            longLivedToken: accessToken, 
            refreshToken,
            expiresIn, 
            platformId,
            profileName,
            followersCount
        };

    } catch (error) {
        console.error('!!! TWITTER TOKEN EXCHANGE FAILED !!!');
        if (error.response) {
            console.error('Status:', error.response.status);
            console.error('Response Data:', error.response.data); 
        }
        // Throw a generic error for the controller
        throw new Error('Twitter authentication failed: Check logs for invalid_request or invalid_client error.');
    }
};

/**
 * Fetches and stores Twitter Insights (Follower Count).
 */
export const fetchAndStoreTwitterInsights = async (socialAccount) => {
    const { accessToken, platformId: userId } = socialAccount;

    // 1. Fetch Follower Count (This section looks generally correct, assuming you save name/followers too)
    const statsRes = await axios.get(`${TWITTER_BASE_URL}/users/${userId}`, {
        params: {
            'user.fields': 'public_metrics,name',
        },
        headers: {
            Authorization: `Bearer ${accessToken}`
        }
    });

    const followersCount = statsRes.data.data.public_metrics.followers_count;
    const profileName = statsRes.data.data.name;

    // --- MongoDB Update ---
    await SocialAccount.updateOne(
        { _id: socialAccount._id },
        { 
            followersCount,
            profileName,
            lastSynced: new Date(),
        }
    );

    return {
        followers: followersCount,
    };
};