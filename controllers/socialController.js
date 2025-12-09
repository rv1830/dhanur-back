// controllers/socialController.js

import asyncHandler from 'express-async-handler';
import jwt from 'jsonwebtoken'; 

// --- Models ---
import SocialAccount from '../models/SocialAccount.js';

// --- Services ---
// (Assuming these files are correctly located in the '../services/' directory)
import * as metaService from '../services/metaService.js';
import * as linkedInService from '../services/linkedInService.js';
// ✅ NEW SERVICE IMPORTS
import * as snapchatService from '../services/snapchatService.js';
import * as youtubeService from '../services/youtubeService.js';
import * as twitterService from '../services/twitterService.js';


// =================================================================
// 🔗 handleCallback: Third-Party OAuth Redirect Handler
// =================================================================

/**
 * @desc    Handles the OAuth callback from social platforms (Now supports 6 platforms)
 * @route   GET /api/social/callback/:platform?code=...&state=...&token=...
 * @access  Public (Authentication done via JWT passed in the 'token' query param)
 */
export const handleCallback = asyncHandler(async (req, res, next) => {
    // 🛑 FIX: Extract 'platform' from req.params
    const { platform } = req.params; 
    // JWT is read from the frontend redirect URL
    const { code, state, token } = req.query; 

    console.log('--- Backend Callback Debugging ---');
    console.log(`Platform: ${platform}`);
    console.log(`Received Code: ${code ? 'Yes' : 'No'}`);
    console.log(`Received Token: ${token ? 'YES, starts with ' + token.substring(0, 10) : 'No'}`); 

    if (!code) {
        res.status(400);
        throw new Error('Authorization code missing.');
    }

    // --- 1. Manual JWT Verification and User ID Extraction ---
    let userId;
    
    if (token) {
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET); 
            userId = decoded.id; 
            console.log('JWT Verification SUCCESS. Decoded User ID:', userId);

        } catch (error) {
            console.error('!!! JWT Verification FAILED in handleCallback !!!');
            console.error(`Error Type: ${error.name}, Message: ${error.message}`);
            
            res.status(401);
            throw new Error('Not authorized, invalid token provided in callback.');
        }
    }

    if (!userId) { 
        console.error('FATAL: Token was either missing or failed verification, and no userId was set.');
        res.status(401); 
        throw new Error('User not authenticated for social callback (Missing/Invalid Token).'); 
    }
    // ----------------------------------------------------------------------
    
    // NOTE: redirectUri logic is slightly platform-dependent. Using FRONTEND_URL/social/callback/ as base.
    let redirectUri = `${process.env.FRONTEND_URL}/social/callback/${platform}`; 
    let tokenData; 
    let platformKey;

    if (platform === 'instagram') {
        platformKey = 'INSTAGRAM';
        
        // Meta uses a different redirect base, adjust if needed, or stick to the unified approach
        tokenData = await metaService.getMetaLongLivedToken(code, redirectUri, platform);
        
        if (!tokenData.platformId) {
            res.status(400);
            throw new Error('Instagram Business Account not found or not linked to Facebook Page.');
        }

    } else if (platform === 'facebook') {
        platformKey = 'FACEBOOK';
        
        tokenData = await metaService.getMetaLongLivedToken(code, redirectUri, platform); 
        
        if (!tokenData.platformId) {
            res.status(400);
            throw new Error('Facebook Page not found.');
        }

    } else if (platform === 'linkedin') {
        platformKey = 'LINKEDIN';
        // LinkedIn often requires a specific, single, pre-registered URI
        redirectUri = process.env.LINKEDIN_REDIRECT_URI; 
        
        tokenData = await linkedInService.getLinkedInAccessToken(code, redirectUri);
        
        if (!tokenData.platformId) {
            res.status(400);
            throw new Error('LinkedIn profile not found.');
        }

    } else if (platform === 'youtube') { // ✅ YOUTUBE LOGIC ADDED
        platformKey = 'YOUTUBE';
        tokenData = await youtubeService.getYoutubeAccessToken(code, redirectUri);
        
        if (!tokenData.platformId) {
            res.status(400);
            throw new Error('YouTube channel not found for the authenticated user.');
        }
        
    } else if (platform === 'snapchat') { // ✅ SNAPCHAT LOGIC ADDED
        platformKey = 'SNAPCHAT';
        tokenData = await snapchatService.getSnapchatAccessToken(code, redirectUri);
        
        if (!tokenData.platformId) {
            res.status(400);
            throw new Error('Snapchat User ID not found.');
        }

    } else if (platform === 'twitter') { // ✅ TWITTER LOGIC ADDED
        platformKey = 'TWITTER';
        // ⚠️ PKCE note: We assume frontend provided the necessary 'code_verifier' 
        // to the service function, though it's simplified here.
        tokenData = await twitterService.getTwitterAccessToken(code, redirectUri);
        
        if (!tokenData.platformId) {
            res.status(400);
            throw new Error('Twitter User ID not found.');
        }

    } else {
        res.status(400);
        throw new Error('Invalid platform specified.');
    }

    // --- Common Logic for All Platforms ---
    if (tokenData) {
        const tokenExpires = new Date(Date.now() + tokenData.expiresIn * 1000);

        const account = await SocialAccount.findOneAndUpdate(
            { userId, platform: platformKey }, 
            {
                platformId: tokenData.platformId,
                accessToken: tokenData.longLivedToken,
                tokenExpires: tokenExpires,
            },
            { upsert: true, new: true }
        );

        // Trigger initial data fetch immediately
        if (platformKey === 'INSTAGRAM') {
            await metaService.fetchAndStoreInstagramInsights(account);
        } else if (platformKey === 'FACEBOOK') {
            await metaService.fetchAndStoreFacebookInsights(account);
        } else if (platformKey === 'LINKEDIN') {
            await linkedInService.fetchAndStoreLinkedInInsights(account);
        } else if (platformKey === 'YOUTUBE') { // ✅ YOUTUBE SYNC
            await youtubeService.fetchAndStoreYoutubeInsights(account);
        } else if (platformKey === 'SNAPCHAT') { // ✅ SNAPCHAT SYNC
            await snapchatService.fetchAndStoreSnapchatInsights(account);
        } else if (platformKey === 'TWITTER') { // ✅ TWITTER SYNC
            await twitterService.fetchAndStoreTwitterInsights(account);
        }


        const frontendRedirect = process.env.FRONTEND_URL || 'http://localhost:3000';
        res.redirect(`${frontendRedirect}?sync_status=${platformKey}_SUCCESS`);
    }
});

// =================================================================
// 🔄 syncAccountData: Manual Sync Handler (PROTECTED)
// =================================================================

/**
 * @desc    Manually triggers an insights sync for a connected social account
 * @route   POST /api/social/sync/:platform
 * @access  Private (Requires JWT from 'protect' middleware)
 */
export const syncAccountData = asyncHandler(async (req, res) => {
    // This route is protected by authMiddleware, so req.user is guaranteed.
    const { platform } = req.params;
    const userId = req.user._id; // ✅ This is safe here

    const socialAccount = await SocialAccount.findOne({ userId, platform: platform.toUpperCase() });

    if (!socialAccount) {
        res.status(404);
        throw new Error('Account not found. Please connect it first.');
    }
    
    let result;
    const platformKey = platform.toLowerCase();

    // ✅ UPDATED: Added new platforms to sync logic
    if (platformKey === 'instagram') {
        result = await metaService.fetchAndStoreInstagramInsights(socialAccount);
    } else if (platformKey === 'facebook') {
        result = await metaService.fetchAndStoreFacebookInsights(socialAccount);
    } else if (platformKey === 'linkedin') {
        result = await linkedInService.fetchAndStoreLinkedInInsights(socialAccount);
    } else if (platformKey === 'youtube') {
        result = await youtubeService.fetchAndStoreYoutubeInsights(socialAccount);
    } else if (platformKey === 'snapchat') {
        result = await snapchatService.fetchAndStoreSnapchatInsights(socialAccount);
    } else if (platformKey === 'twitter') {
        result = await twitterService.fetchAndStoreTwitterInsights(socialAccount);
    } else {
        res.status(501);
        throw new Error('Sync not implemented for this platform.');
    }

    res.json({ success: true, data: result });
});

// =================================================================
// 🔍 getSocialAccountDetails: Fetches Account Details (PROTECTED)
// =================================================================

/**
 * @desc    Get details for a connected social account
 * @route   GET /api/social/account/:platform
 * @access  Private (Requires JWT from 'protect' middleware)
 */
export const getSocialAccountDetails = asyncHandler(async (req, res) => {
    // req.user is guaranteed here by 'protect' middleware
    const { platform } = req.params;
    const userId = req.user._id;

    // Convert platform slug to uppercase (e.g., 'linkedin' -> 'LINKEDIN')
    const platformKey = platform.toUpperCase();

    // Find the linked account for the logged-in user and specified platform
    const socialAccount = await SocialAccount.findOne({ userId, platform: platformKey });

    if (!socialAccount) {
        res.status(404);
        throw new Error(`Social account not connected for ${platformKey}.`);
    }

    // Return the necessary details to the frontend
    res.json({
        success: true,
        platform: platformKey,
        platformId: socialAccount.platformId,
        followersCount: socialAccount.followersCount,
        profileName: socialAccount.profileName, // Assuming you added this field to the model
        lastSynced: socialAccount.lastSynced,
        // Do NOT return accessToken or tokenExpires
    });
});