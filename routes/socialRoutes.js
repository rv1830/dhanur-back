// routes/socialRoutes.js (UPDATED with new Analytics route)

import express from 'express';
// Note: getYouTubeAnalyticsData को भी import किया गया है
import { 
handleCallback,
syncAccountData,
getSocialAccountDetails,
getYouTubeAnalyticsData ,
disconnectSocialAccount} from '../controllers/socialController.js'; 
import { protect } from '../middleware/authMiddleware.js';

const router = express.Router();


router.get('/callback/:platform', protect, handleCallback);

// ✅ Sync route protected rahega (user manually call karta hai after login)
router.post('/sync/:platform', protect, syncAccountData);
router.get('/account/:platform', protect, getSocialAccountDetails);

// ✅ NEW ANALYTICS GET API
router.get('/analytics/youtube', protect, getYouTubeAnalyticsData);
router.delete('/disconnect/:platform', protect, disconnectSocialAccount);
export default router;