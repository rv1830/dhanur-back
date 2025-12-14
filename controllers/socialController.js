// controllers/socialController.js (UPDATED WITH CORRECT REDIRECT)

import asyncHandler from 'express-async-handler';

// --- Models ---
import SocialAccount from '../models/SocialAccount.js';

// --- Services ---
import * as metaService from '../services/metaService.js';
import * as linkedInService from '../services/linkedInService.js';
import * as snapchatService from '../services/snapchatService.js';
import * as youtubeService from '../services/youtubeService.js';
import * as twitterService from '../services/twitterService.js';

// =================================================================
// 🔗 handleCallback: Third-Party OAuth Redirect Handler (PROTECTED)
// =================================================================

/**
 * @desc    Handles the OAuth callback from social platforms
 * @route   GET /api/social/callback/:platform?code=...&state=...
 * @access  Private (Relies on 'protect' middleware to set req.user)
 */
export const handleCallback = asyncHandler(async (req, res, next) => {
    const { platform } = req.params; 
    const { code, state, code_verifier } = req.query; 

    // User ID from protect middleware
    const userId = req.user._id;

    console.log('--- Backend Callback Debugging ---');
    console.log(`Platform: ${platform}`);
    console.log(`Received Code: ${code ? 'Yes' : 'No'}`);
    console.log(`Authenticated User ID (from Cookie/Protect): ${userId}`);
    console.log(`Received Code Verifier (PKCE): ${code_verifier ? 'Yes' : 'No'}`);

    if (!code) {
        res.status(400);
        throw new Error('Authorization code missing.');
    }
    
    let redirectUri = `${process.env.FRONTEND_URL}/social/callback/${platform}`; 
    let tokenData;
    let platformKey;

    if (platform === 'instagram') {
        platformKey = 'INSTAGRAM';
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
        redirectUri = process.env.LINKEDIN_SOCIAL_REDIRECT_URI; 
        
        tokenData = await linkedInService.getLinkedInAccessToken(code, redirectUri);
        
        if (!tokenData.platformId) {
            res.status(400);
            throw new Error('LinkedIn profile not found.');
        }

    } else if (platform === 'youtube') {
        platformKey = 'YOUTUBE';
        tokenData = await youtubeService.getYoutubeAuthData(code, redirectUri);
        
        if (!tokenData.platformId) {
            res.status(400);
            throw new Error('YouTube channel not found for the authenticated user.');
        }
        
    } else if (platform === 'snapchat') {
        platformKey = 'SNAPCHAT';
        
        const codeVerifier = code_verifier; 
        
        if (!codeVerifier) {
            res.status(400);
            throw new Error('PKCE code verifier is missing. Cannot complete Snapchat authentication.');
        }
        
        tokenData = await snapchatService.getSnapchatAccessToken(code, redirectUri, codeVerifier);
        
        if (!tokenData.platformId) {
            res.status(400);
            throw new Error('Snapchat User ID not found.');
        }

    } else if (platform === 'twitter') {
        platformKey = 'TWITTER';
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

        const updateFields = {
            platformId: tokenData.platformId,
            accessToken: tokenData.accessToken || tokenData.longLivedToken, 
            refreshToken: tokenData.refreshToken,
            tokenExpires: tokenExpires,
            profileName: tokenData.profileName,
            followersCount: tokenData.followersCount,
            profilePictureUrl: tokenData.profilePictureUrl,
            channelDescription: tokenData.channelDescription,
            totalVideos: tokenData.totalVideos,
            totalViews: tokenData.totalViews,
            lastSynced: new Date(),
        };

        const account = await SocialAccount.findOneAndUpdate(
            { userId, platform: platformKey }, 
            { $set: updateFields },
            { upsert: true, new: true }
        );

        // Trigger initial data fetch
        if (platformKey === 'INSTAGRAM') {
            await metaService.fetchAndStoreInstagramInsights(account);
        } else if (platformKey === 'FACEBOOK') {
            await metaService.fetchAndStoreFacebookInsights(account);
        } else if (platformKey === 'LINKEDIN') {
             await linkedInService.fetchAndStoreLinkedInInsights(account);
        } else if (platformKey === 'YOUTUBE') {
            await youtubeService.fetchAndStoreYoutubeKPIs(account); 
        } else if (platformKey === 'SNAPCHAT') {
            await snapchatService.fetchAndStoreSnapchatInsights(account);
        } else if (platformKey === 'TWITTER') {
            await twitterService.fetchAndStoreTwitterInsights(account);
        }

        const frontendRedirect = process.env.FRONTEND_URL || 'http://localhost:3000';
        
        // ✅ FIXED: Redirect directly to influencer dashboard connect page
        let redirectUrl = `${frontendRedirect}/dashboard/influencer/connect`;
        
        // Add query parameters
        const params = new URLSearchParams({
            social_connected: 'true',
            platform: platformKey,
            success: 'true',
            timestamp: Date.now().toString()
        });
        
        if (tokenData.profileName) {
            params.append('channel', tokenData.profileName);
        }
        
        if (tokenData.followersCount) {
            params.append('followers', tokenData.followersCount);
        }
        
        redirectUrl += `?${params.toString()}`;
        
        console.log(`✅ FINAL REDIRECT TO: ${redirectUrl}`);
        res.redirect(redirectUrl);
    }
});

// =================================================================
// 🔄 syncAccountData: Manual Sync Handler (PROTECTED)
// =================================================================

export const syncAccountData = asyncHandler(async (req, res) => {
    const { platform } = req.params;
    const userId = req.user._id;

    const socialAccount = await SocialAccount.findOne({ userId, platform: platform.toUpperCase() });

    if (!socialAccount) {
        res.status(404);
        throw new Error('Account not found. Please connect it first.');
    }
    
    let result;
    const platformKey = platform.toLowerCase();

    if (platformKey === 'instagram') {
        result = await metaService.fetchAndStoreInstagramInsights(socialAccount);
    } else if (platformKey === 'facebook') {
        result = await metaService.fetchAndStoreFacebookInsights(socialAccount);
    } else if (platformKey === 'linkedin') {
        result = await linkedInService.fetchAndStoreLinkedInInsights(socialAccount);
    } else if (platformKey === 'youtube') {
        result = await youtubeService.fetchAndStoreYoutubeKPIs(socialAccount);
        await youtubeService.fetchAndStoreYoutubeProfile(socialAccount);
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

export const getSocialAccountDetails = asyncHandler(async (req, res) => {
    const { platform } = req.params;
    const userId = req.user._id;

    const platformKey = platform.toUpperCase();

    const socialAccount = await SocialAccount.findOne({ userId, platform: platformKey });

    if (!socialAccount) {
        res.status(404);
        throw new Error(`Social account not connected for ${platformKey}.`);
    }

    res.json({
        success: true,
        platform: platformKey,
        platformId: socialAccount.platformId,
        profileName: socialAccount.profileName, 
        followersCount: socialAccount.followersCount,
        profilePictureUrl: socialAccount.profilePictureUrl,
        totalVideos: socialAccount.totalVideos,
        totalViews: socialAccount.totalViews,
        lastSynced: socialAccount.lastSynced,
    });
});