import express from 'express';
import {
    // Basic Auth
    registerUser,
    authUser,
    // Protected
    logoutUser,
    changePassword,
    checkAuthStatus,
    // Profile Setup (NEW)
    setupProfile,
    // Google Auth
    googleSignup,
    googleLogin,
    googleCallback,
    // LinkedIn Auth
    linkedinSignup,
    linkedinLogin,
    linkedinCallback,
    // OTP & Reset
    sendResetCode,
    resetPassword,
    // User Type Selection
    selectUserType,
} from '../controllers/authController.js';
import { protect } from '../middleware/authMiddleware.js';

const router = express.Router();

// =======================
// 🔑 PUBLIC ROUTES
// =======================

// ✅ Basic Email/Password Auth
router.post('/register', registerUser); 
router.post('/login', authUser);

// ✅ Google OAuth
router.get('/google/signup', googleSignup);
router.get('/google/login', googleLogin);
router.get('/google/callback', googleCallback);

// ✅ LinkedIn OAuth
router.get('/linkedin/signup', linkedinSignup);
router.get('/linkedin/login', linkedinLogin);
router.get('/linkedin/callback', linkedinCallback);

// ✅ Password Reset
router.post('/reset/send', sendResetCode);
router.post('/reset', resetPassword);

// =======================
// 🔒 PROTECTED ROUTES
// =======================
router.post('/logout', protect, logoutUser);
router.post('/change-password', protect, changePassword);
router.get('/check-status', protect, checkAuthStatus);

// ✅ NEW: Profile Setup Route (Step 1 after signup)
router.post('/profile-setup', protect, setupProfile);

// ✅ User Type Selection (Step 2 after profile setup)
router.post('/select-usertype', protect, selectUserType);

export default router;