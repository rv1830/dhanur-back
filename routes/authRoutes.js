import express from 'express';
import {
    // Basic Auth
    registerUser,
    authUser,
    // Protected
    logoutUser,
    changePassword,
    checkAuthStatus,
    // Google Auth (Unified Callback)
    googleSignup,
    googleLogin,
    googleCallback,
    // LinkedIn Auth (Unified Callback)
    linkedinSignup,
    linkedinLogin,
    linkedinCallback,
    // OTP & Reset
    sendOtp,
    verifyOtp,
    sendResetCode,
    resetPassword,
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

// ✅ Google Signup & Login (uses state markers)
router.get('/google/signup', googleSignup);
router.get('/google/login', googleLogin);
router.get('/google/callback', googleCallback); // Single unified callback

// ✅ LinkedIn Signup & Login (uses state markers)
router.get('/linkedin/signup', linkedinSignup);
router.get('/linkedin/login', linkedinLogin);
router.get('/linkedin/callback', linkedinCallback); // Single unified callback

// ✅ OTP Login (Phone)
router.post('/otp/send', sendOtp);
router.post('/otp/verify', verifyOtp);

// ✅ Password Reset
router.post('/reset/send', sendResetCode);
router.post('/reset', resetPassword);

// =======================
// 🔒 PROTECTED ROUTES
// =======================
router.post('/logout', protect, logoutUser);
router.post('/change-password', protect, changePassword);
router.get('/check-status', protect, checkAuthStatus);
router.post('/select-usertype', protect, selectUserType); // ✅ New UserType Route

export default router;