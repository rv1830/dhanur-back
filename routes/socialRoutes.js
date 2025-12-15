// routes/socialRoutes.js (UPDATED with new Analytics route)

import express from 'express';
import { protect } from '../middleware/authMiddleware.js';
import {
    handleCallback,
    syncAccountData,
    getSocialAccountDetails,
    getYouTubeAnalyticsData,
    getMetaAnalyticsData, // 👈 NEW: Meta Analytics Controller
    disconnectSocialAccount,
} from '../controllers/socialController.js';

const router = express.Router();

// 🔗 OAuth Callback (Publicly accessible, but depends on token from client)
router.get('/callback/:platform', protect, handleCallback);

// 🔄 Manual Sync (Protected)
router.post('/sync/:platform', protect, syncAccountData);

// 🔍 Account Details Fetch (Protected)
router.get('/details/:platform', protect, getSocialAccountDetails);

// 📈 Analytics Data Fetch (Protected)
router.get('/analytics/youtube', protect, getYouTubeAnalyticsData);
// 👈 NEW: Meta Analytics (Instagram/Facebook) के लिए डायनेमिक रूट
router.get('/analytics/:platform', protect, getMetaAnalyticsData); 

// 🗑️ Disconnect Account (Protected)
router.delete('/disconnect/:platform', protect, disconnectSocialAccount);

export default router;