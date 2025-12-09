// routes/socialRoutes.js
import express from 'express';
import { handleCallback, syncAccountData,getSocialAccountDetails } from '../controllers/socialController.js';
import { protect } from '../middleware/authMiddleware.js';

const router = express.Router();

// ✅ Callback route PUBLIC rakhna hai (third-party redirect aata hai, token nahi hota)
// No protect middleware here
router.get('/callback/:platform', handleCallback);

// ✅ Sync route protected rahega (user manually call karta hai after login)
router.post('/sync/:platform', protect, syncAccountData);
router.get('/account/:platform', protect, getSocialAccountDetails);

export default router;