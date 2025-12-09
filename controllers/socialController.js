import asyncHandler from 'express-async-handler';
import jwt from 'jsonwebtoken'; 
import SocialAccount from '../models/SocialAccount.js';
import * as metaService from '../services/metaService.js';
import * as linkedInService from '../services/linkedInService.js';

// =================================================================
// 🔗 handleCallback: Third-Party OAuth Redirect Handler
// =================================================================

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
    
    let redirectUri = `${process.env.META_REDIRECT_BASE}/${platform}`; 
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
        redirectUri = process.env.LINKEDIN_REDIRECT_URI; 
        
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
        }

        const frontendRedirect = process.env.FRONTEND_URL || 'http://localhost:3000';
        res.redirect(`${frontendRedirect}?sync_status=${platformKey}_SUCCESS`);
    }
});

// =================================================================
// 🔄 syncAccountData: Manual Sync Handler (PROTECTED)
// =================================================================

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

// controllers/socialController.js (Add this new function)

// ... (existing imports: asyncHandler, jwt, SocialAccount, etc.)

// 💡 NEW FUNCTION
// @desc    Get details for a connected social account
// @route   GET /api/social/account/:platform
// @access  Private (Requires JWT)
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

// ... (handleCallback and syncAccountData functions remain above this)