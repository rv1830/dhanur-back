// --- controllers/socialController.js (FINAL UPDATED) ---

import asyncHandler from 'express-async-handler';

// --- Models ---
import SocialAccount from '../models/SocialAccount.js';
import YouTubeAnalytics from '../models/YouTubeAnalytics.js'; 
import FacebookAnalytics from '../models/FacebookAnalytics.js'; 
import InstagramAnalytics from '../models/InstagramAnalytics.js'; 
import crypto from 'crypto'; 

// --- Services ---
import * as metaService from '../services/metaService.js'; 
import * as facebookService from '../services/facebookService.js'; 
import * as instagramService from '../services/instagramService.js'; 
import * as linkedInService from '../services/linkedInService.js';
import * as snapchatService from '../services/snapchatService.js';
import * as youtubeService from '../services/youtubeService.js';
import * as twitterService from '../services/twitterService.js';

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
const META_BASE_URL_OAUTH = 'https://www.facebook.com/v18.0/dialog/oauth';

// =================================================================
// 🔗 connectMetaAccount: Social Connect Start
// =================================================================

/**
 * @desc    Initiates the Meta (FB/IG) OAuth flow for Social Account Connection
 * @route   GET /api/social/connect/:platform
 * @access  Private (Protect middleware required)
 */
export const connectMetaAccount = (req, res) => {
    const { platform } = req.params; // 'facebook' or 'instagram'
    const redirectUri = process.env.META_SOCIAL_REDIRECT_URI; 
    
    let scopeFinal;
    if (platform === 'facebook') {
        // Scopes for Facebook Page connection and insights
        scopeFinal = 'email,public_profile,pages_show_list,pages_read_engagement,read_insights,manage_pages';
    } else if (platform === 'instagram') {
        // Scopes for Instagram Business connection and insights
        scopeFinal = 'email,public_profile,pages_show_list,instagram_basic,instagram_manage_insights,pages_read_engagement'; 
    } else {
        res.status(400);
        throw new Error('Invalid platform for Meta Connect.');
    }
    
    // 🚨 STABLE ID CHANGE: Using req.user.uid instead of _id for the state
    const state = `connect_${platform}:${req.user.uid}:${crypto.randomBytes(8).toString('hex')}`; 

    const authUrl = `${META_BASE_URL_OAUTH}?` +
        `client_id=${process.env.META_APP_ID}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&state=${state}` +
        `&response_type=code` +
        `&scope=${encodeURIComponent(scopeFinal)}`;
        
    res.redirect(authUrl);
};


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

    // User ID from protect middleware (Internal ID remains for DB relationships)
    const userId = req.user._id;

    console.log('--- Backend Callback Debugging ---');
    console.log(`Platform: ${platform}`);
    console.log(`Received Code: ${code ? 'Yes' : 'No'}`);
    console.log(`Authenticated User UID (from Protect): ${req.user.uid}`);
    console.log(`Received Code Verifier (PKCE): ${code_verifier ? 'Yes' : 'No'}`);

    if (!code) {
        res.status(400);
        throw new Error('Authorization code missing.');
    }
    
    // Default redirectUri (used for platforms that don't need a specific redirectUri env variable for token exchange)
    let redirectUri = `${FRONTEND_URL}/social/callback/${platform}`; 
    let tokenData;
    let platformKey = platform.toUpperCase();

    if (platformKey === 'INSTAGRAM' || platformKey === 'FACEBOOK') {
        // 1. Get Long-Lived User Token (common step for Meta)
        const metaRedirectUri = process.env.META_SOCIAL_REDIRECT_URI;
        const metaTokenData = await metaService.getMetaLongLivedToken(code, metaRedirectUri);
        const { longLivedToken, expiresIn } = metaTokenData;

        // 2. Fetch platform-specific data using the longLivedToken
        if (platformKey === 'INSTAGRAM') {
            console.log('Fetching Instagram-specific account data...');
            tokenData = await instagramService.getInstagramAuthData(code, metaRedirectUri, longLivedToken);
            tokenData.expiresIn = expiresIn; // Attach expiresIn
        } else if (platformKey === 'FACEBOOK') {
            console.log('Fetching Facebook-specific page data...');
            tokenData = await facebookService.getFacebookAuthData(code, metaRedirectUri, longLivedToken);
            tokenData.expiresIn = expiresIn; // Attach expiresIn
        }
        
        if (!tokenData.platformId) {
             res.status(400);
             throw new Error(`${platformKey} Account not found or permissions denied.`);
        }

    } else if (platformKey === 'LINKEDIN') {
        redirectUri = process.env.LINKEDIN_SOCIAL_REDIRECT_URI; 
        tokenData = await linkedInService.getLinkedInAccessToken(code, redirectUri);
        
    } else if (platformKey === 'YOUTUBE') {
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
            // Use longLivedToken for Meta platforms, accessToken for others like YouTube
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
            console.log('Triggering initial Instagram Insight Sync...');
            await instagramService.fetchAndStoreInstagramInsights(account); 
        } else if (platformKey === 'FACEBOOK') {
            console.log('Triggering initial Facebook Insight Sync...');
            await facebookService.fetchAndStoreFacebookInsights(account);
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
        
        // ✅ UPDATED PATH: Redirects to /dashboard/connect (Removed /influencer)
        let redirectUrl = `${frontendRedirect}/dashboard/connect`;
        
        // Add query parameters for frontend visibility
        const params = new URLSearchParams({
            social_connected: 'true',
            platform: platformKey,
            success: 'true',
            timestamp: Date.now().toString(),
            uid: req.user.uid // Return public UID for frontend consistency
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
        result = await instagramService.fetchAndStoreInstagramInsights(socialAccount);
    } else if (platformKey === 'facebook') {
        result = await facebookService.fetchAndStoreFacebookInsights(socialAccount);
    } else if (platformKey === 'linkedin') {
        result = await linkedInService.fetchAndStoreLinkedInInsights(socialAccount);
    } else if (platformKey === 'youtube') {
        result = await youtubeService.fetchAndStoreYoutubeKPIs(socialAccount);
        await youtubeService.fetchAndStoreYoutubeProfile(socialAccount);
    } else if (platformKey === 'snapchat') {
        res.status(501);
        throw new Error('Sync not implemented for Snapchat.');
    } else if (platformKey === 'twitter') {
        res.status(501);
        throw new Error('Sync not implemented for Twitter.');
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


// =================================================================
// 📈 getYouTubeAnalyticsData: Fetches YouTube KPI Data (PROTECTED)
// =================================================================

/**
 * @desc    Fetches stored YouTube Analytics data (KPIs) for the connected account
 * @route   GET /api/social/analytics/youtube
 * @access  Private (Relies on 'protect' middleware to set req.user)
 */
export const getYouTubeAnalyticsData = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    const platformKey = 'YOUTUBE'; // Hardcode platform for this specific API

    // 1. Find the Social Account ID
    const socialAccount = await SocialAccount.findOne({ userId, platform: platformKey });

    if (!socialAccount) {
        res.status(404);
        throw new Error(`YouTube account not connected.`);
    }
    
    // 2. Fetch stored Analytics data for that socialAccountId (e.g., last 90 days)
    const analyticsData = await YouTubeAnalytics.find({ 
        socialAccountId: socialAccount._id 
    })
    .sort({ date: -1 }) // Sort by descending date (newest first)
    .limit(90); // Fetch last 90 days of data

    // 3. Prepare the response
    const formattedData = analyticsData.map(data => ({
        date: data.date.toISOString().split('T')[0], // YYYY-MM-DD format
        views: data.views,
        comments: data.comments,
        likes: data.likes,
        shares: data.shares,
        subscribersGained: data.subscribersGained,
        watchTimeMinutes: data.watchTimeMinutes,
        estimatedRevenue: data.estimatedRevenue, 
        adImpressions: data.adImpressions,
    }));

    res.json({
        success: true,
        channelName: socialAccount.profileName,
        totalRecords: formattedData.length,
        data: formattedData,
    });
});


// =================================================================
// 📈 getInstagramAnalyticsData: Fetches Instagram KPI Data (NEW API)
// =================================================================

/**
 * @desc    Fetches stored Instagram Analytics data (KPIs)
 * @route   GET /api/social/analytics/instagram
 * @access  Private 
 */
export const getInstagramAnalyticsData = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    const platformKey = 'INSTAGRAM';

    const socialAccount = await SocialAccount.findOne({ userId, platform: platformKey });

    if (!socialAccount) {
        res.status(404);
        throw new Error(`${platformKey} account not connected.`);
    }
    
    // 2. Fetch stored Analytics data for Instagram
    const analyticsData = await InstagramAnalytics.find({ 
        socialAccountId: socialAccount._id 
    })
    .sort({ date: -1 }) 
    .limit(90); 

    // 3. Prepare the response
    const formattedData = analyticsData.map(data => ({
        date: data.date.toISOString().split('T')[0], 
        reach: data.reach,
        impressions: data.impressions,
        profileViews: data.profileViews,
        engagement: data.engagement,
        postReactions: data.postReactions,
    }));

    res.json({
        success: true,
        profileName: socialAccount.profileName,
        platform: platformKey,
        totalRecords: formattedData.length,
        data: formattedData,
    });
});


// =================================================================
// 📈 getFacebookAnalyticsData: Fetches Facebook KPI Data (NEW API)
// =================================================================

/**
 * @desc    Fetches stored Facebook Analytics data (KPIs)
 * @route   GET /api/social/analytics/facebook
 * @access  Private 
 */
export const getFacebookAnalyticsData = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    const platformKey = 'FACEBOOK';

    const socialAccount = await SocialAccount.findOne({ userId, platform: platformKey });

    if (!socialAccount) {
        res.status(404);
        throw new Error(`${platformKey} account not connected.`);
    }
    
    // 2. Fetch stored Analytics data for Facebook
    const analyticsData = await FacebookAnalytics.find({ 
        socialAccountId: socialAccount._id 
    })
    .sort({ date: -1 }) 
    .limit(90); 

    // 3. Prepare the response
    const formattedData = analyticsData.map(data => ({
        date: data.date.toISOString().split('T')[0], 
        pageImpressions: data.pageImpressions,
        pageEngagedUsers: data.pageEngagedUsers,
        pageViewsTotal: data.pageViewsTotal,
        pageFanCount: data.pageFanCount,
    }));

    res.json({
        success: true,
        profileName: socialAccount.profileName,
        platform: platformKey,
        totalRecords: formattedData.length,
        data: formattedData,
    });
});


// =================================================================
// 🗑️ disconnectSocialAccount: Removes Account Connection (UPDATED API)
// =================================================================

/**
 * @desc    Disconnects/Deletes a social media account connection from the DB
 * @route   DELETE /api/social/disconnect/:platform
 * @access  Private (Relies on 'protect' middleware to set req.user)
 */
export const disconnectSocialAccount = asyncHandler(async (req, res) => {
    const { platform } = req.params;
    const userId = req.user._id;

    const platformKey = platform.toUpperCase();

    // 1. SocialAccount रिकॉर्ड को ढूंढें और हटाएँ
    const deletedAccount = await SocialAccount.findOneAndDelete({ 
        userId, 
        platform: platformKey 
    });

    if (!deletedAccount) {
        // यदि अकाउंट मिला ही नहीं, तो भी success status भेजें 
        res.status(200).json({ 
            success: true, 
            message: `${platformKey} account was already disconnected or not found.` 
        });
        return;
    }
    
    // 2. Analytics Data Clean-up 
    if (platformKey === 'YOUTUBE') {
        const deleteResult = await YouTubeAnalytics.deleteMany({ 
            socialAccountId: deletedAccount._id 
        });
        console.log(`[CLEANUP] Deleted ${deleteResult.deletedCount} YouTube Analytics records.`);
    } else if (platformKey === 'INSTAGRAM') { 
        const deleteResult = await InstagramAnalytics.deleteMany({ 
            socialAccountId: deletedAccount._id 
        });
        console.log(`[CLEANUP] Deleted ${deleteResult.deletedCount} Instagram Analytics records.`);
    } else if (platformKey === 'FACEBOOK') { 
        const deleteResult = await FacebookAnalytics.deleteMany({ 
            socialAccountId: deletedAccount._id 
        });
        console.log(`[CLEANUP] Deleted ${deleteResult.deletedCount} Facebook Analytics records.`);
    }

    res.json({
        success: true,
        message: `${deletedAccount.profileName} (${platformKey}) successfully disconnected and data cleaned up.`,
        platform: platformKey
    });
});