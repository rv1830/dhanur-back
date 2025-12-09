// controllers/socialController.js
import asyncHandler from 'express-async-handler';
import SocialAccount from '../models/SocialAccount.js';
import * as metaService from '../services/metaService.js';
import * as linkedInService from '../services/linkedInService.js';

// NOTE: req.user is populated by the authMiddleware
export const handleCallback = asyncHandler(async (req, res, next) => {
    const { platform } = req.params;
    const { code, state } = req.query; // Added state for CSRF protection

    if (!code) {
        res.status(400);
        throw new Error('Authorization code missing.');
    }

    // TODO: Verify state against session-stored state (implement session or pass from frontend)
    // For now, assuming state is verified in frontend or skipping for MVP
    // In production: if (state !== req.session.oauthState) { throw new Error('Invalid state'); }

    const userId = req.user._id;
    let redirectUri = `${process.env.META_REDIRECT_BASE}/${platform}`; // Fixed: Use base + platform
    let tokenData; // To hold { longLivedToken, expiresIn, platformId }
    let platformKey;

    if (platform === 'instagram') {
        platformKey = 'INSTAGRAM';
        
        // --- 1. Instagram Logic ---
        // Fetch IG Business ID and Long-Lived Token
        tokenData = await metaService.getMetaLongLivedToken(code, redirectUri, platform);
        
        if (!tokenData.platformId) {
            res.status(400);
            throw new Error('Instagram Business Account not found or not linked to Facebook Page.');
        }

    } else if (platform === 'facebook') {
        platformKey = 'FACEBOOK';
        
        // --- 2. Facebook Logic ---
        tokenData = await metaService.getMetaLongLivedToken(code, redirectUri, platform);
        
        if (!tokenData.platformId) {
            res.status(400);
            throw new Error('Facebook Page not found.');
        }

    } else if (platform === 'linkedin') {
        platformKey = 'LINKEDIN';
        redirectUri = process.env.LINKEDIN_REDIRECT_URI; // LinkedIn has separate redirect
        
        // --- 3. LinkedIn Logic ---
        tokenData = await linkedInService.getLinkedInAccessToken(code, redirectUri);
        
        if (!tokenData.platformId) {
            res.status(400);
            throw new Error('LinkedIn profile not found.');
        }

    } else {
        res.status(400);
        throw new Error('Invalid platform specified.');
    }

    // --- Common Logic for All Platforms ---
    if (tokenData) {
        // Calculate expiration date
        const tokenExpires = new Date(Date.now() + tokenData.expiresIn * 1000);

        // Upsert (Update or Insert) the SocialAccount
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
        }

        res.json({ success: true, message: `${platformKey} connected and data synced.` });
    }
});

export const syncAccountData = asyncHandler(async (req, res) => {
    const { platform } = req.params;
    const userId = req.user._id;

    const socialAccount = await SocialAccount.findOne({ userId, platform: platform.toUpperCase() });

    if (!socialAccount) {
        res.status(404);
        throw new Error('Account not found. Please connect it first.');
    }

    let result;
    if (platform === 'instagram') {
        result = await metaService.fetchAndStoreInstagramInsights(socialAccount);
    } else if (platform === 'facebook') {
        result = await metaService.fetchAndStoreFacebookInsights(socialAccount);
    } else if (platform === 'linkedin') {
        result = await linkedInService.fetchAndStoreLinkedInInsights(socialAccount);
    } else {
        res.status(501);
        throw new Error('Sync not implemented for this platform.');
    }

    res.json({ success: true, data: result });
});