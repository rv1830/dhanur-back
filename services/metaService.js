// --- services/metaService.js (UPDATED - Only for Token Exchange) ---
import axios from 'axios';

const META_BASE_URL = 'https://graph.facebook.com/v18.0';

/**
 * Exchanges short-lived code for a Long-Lived Access Token.
 * This token is a user token, not a page token.
 * It is used by both Facebook and Instagram connection flows initially.
 */
export const getMetaLongLivedToken = async (code, redirectUri) => {
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

    // 3. Fetch User Profile to get FB User ID and Email
    const profileRes = await axios.get(`${META_BASE_URL}/me`, {
        params: {
            fields: 'id,name,email,picture', 
            access_token: longLivedToken
        }
    });

    return { 
        longLivedToken, 
        expiresIn, 
        fbUserId: profileRes.data.id,
        userEmail: profileRes.data.email,
        userName: profileRes.data.name,
        profilePicture: profileRes.data.picture?.data?.url
    };
};