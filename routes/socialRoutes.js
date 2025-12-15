// --- routes/socialRoutes.js (UPDATED for FB/IG separation) ---

import express from 'express';
import { protect } from '../middleware/authMiddleware.js';
import {
    connectMetaAccount, // 👈 NEW: Meta Connect Start
    handleCallback,
    syncAccountData,
    getSocialAccountDetails,
    getYouTubeAnalyticsData,
    getInstagramAnalyticsData, // 👈 NEW: Instagram Analytics Controller
    getFacebookAnalyticsData,  // 👈 NEW: Facebook Analytics Controller
    disconnectSocialAccount,
} from '../controllers/socialController.js';

const router = express.Router();

// =======================
// 🔗 SOCIAL CONNECT ROUTES
// =======================

// ✅ NEW: Start the connection flow for Meta platforms
router.get('/connect/:platform', protect, connectMetaAccount); 

// 🔗 OAuth Callback
router.get('/callback/:platform', protect, handleCallback);

// =======================
// 🔄 SYNC & DETAILS
// =======================

// 🔄 Manual Sync (Protected)
router.post('/sync/:platform', protect, syncAccountData);

// 🔍 Account Details Fetch (Protected)
router.get('/account/:platform', protect, getSocialAccountDetails);


// =======================
// 📈 ANALYTICS DATA FETCH
// =======================

// ✅ YouTube Analytics
router.get('/analytics/youtube', protect, getYouTubeAnalyticsData);

// ✅ NEW: Instagram Analytics
router.get('/analytics/instagram', protect, getInstagramAnalyticsData);

// ✅ NEW: Facebook Analytics
router.get('/analytics/facebook', protect, getFacebookAnalyticsData);


// =======================
// 🗑️ DISCONNECT
// =======================

// 🗑️ Disconnect Account (Protected)
router.delete('/disconnect/:platform', protect, disconnectSocialAccount);

export default router;