// services/snapchatService.js
import axios from 'axios';
import SocialAccount from '../models/SocialAccount.js';

// --- CONFIGURATION ---
const SNAPCHAT_TOKEN_ENDPOINT = 'https://accounts.snapchat.com/accounts/oauth2/token';
const SNAPCHAT_PROFILE_ENDPOINT = 'https://api.snapchat.com/user/v1/me'; 

/**
 * Exchanges code for Access Token and fetches Snapchat User ID.
 * NOTE: This function expects 'codeVerifier' which must be the original string generated on the frontend.
 */
export const getSnapchatAccessToken = async (code, redirectUri, codeVerifier) => {
    
    // Server-Side Flow with PKCE (Recommended by Snapchat)
    const tokenParams = {
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: redirectUri,
        client_id: process.env.SNAPCHAT_CLIENT_ID,
        client_secret: process.env.SNAPCHAT_CLIENT_SECRET, // Required for Server-Side
        code_verifier: codeVerifier, // PKCE: REQUIRED for validation
    };

    console.log('Attempting Snapchat Token Exchange with PKCE...');
    
    try {
        const tokenRes = await axios.post(SNAPCHAT_TOKEN_ENDPOINT, new URLSearchParams(tokenParams), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });
        
        const accessToken = tokenRes.data.access_token;
        const expiresIn = tokenRes.data.expires_in;

        console.log('Token exchange successful. Fetching profile...');

        // 2. Fetch User Info/ID
        const profileRes = await axios.get(SNAPCHAT_PROFILE_ENDPOINT, {
            headers: {
                Authorization: `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            }
        });

        const platformId = profileRes.data.externalId || profileRes.data.id; 
        const profileName = profileRes.data.displayName;

        if (!platformId) {
            throw new Error("Snapchat User ID not received from profile endpoint.");
        }

        return { 
            longLivedToken: accessToken, 
            expiresIn, 
            platformId,
            profileName 
        };
        
    } catch (error) {
        console.error('!!! SNAPCHAT TOKEN EXCHANGE FAILED !!!');
        if (error.response) {
            console.error('Status:', error.response.status);
            console.error('Response Data:', error.response.data); 
        } else {
            console.error('Error:', error.message);
        }
        throw new Error('Snapchat authentication failed: Check Client Secret, Redirect URI, and PKCE verifier.');
    }
};

/**
 * Fetches and stores Snapchat Insights (Placeholder/Mock Logic)
 */
export const fetchAndStoreSnapchatInsights = async (socialAccount) => {
    // --- Mock Logic for MVP ---
    let followersCount = Math.floor(Math.random() * 50000) + 10000; 

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