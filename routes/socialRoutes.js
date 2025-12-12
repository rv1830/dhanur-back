// routes/socialRoutes.js

import express from 'express';
import { handleCallback, syncAccountData, getSocialAccountDetails } from '../controllers/socialController.js';
import { protect } from '../middleware/authMiddleware.js';

const router = express.Router();

// ✅ FIX 1: handleCallback को अब PROTECT middleware के पीछे रखा जाएगा।
// यह सुनिश्चित करता है कि जब सोशल मीडिया से रीडायरेक्ट वापस आता है, 
// तो ब्राउज़र अपनी HTTP-only 'token' कुकी को अनुरोध (request) के साथ भेजता है।
router.get('/callback/:platform', protect, handleCallback);

// ✅ Sync route protected rahega (user manually call karta hai after login)
router.post('/sync/:platform', protect, syncAccountData);
router.get('/account/:platform', protect, getSocialAccountDetails);

export default router;