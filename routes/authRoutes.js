// routes/authRoutes.js
import express from 'express';
import {
    // Basic Auth
    registerUser,
    authUser,
    // Protected
    logoutUser,
    changePassword,
    checkAuthStatus,
    // Social & Utility Auth
    googleLogin, googleCallback,
    linkedinLogin, linkedinCallback,
    sendOtp, verifyOtp,
    sendResetCode, resetPassword,
} from '../controllers/authController.js';
import { protect } from '../middleware/authMiddleware.js'; // Updated import

const router = express.Router();

// =======================
// 🔑 Public Routes
// =======================

// Basic Email/Password (from former userRoutes)
router.post('/register', registerUser); 
router.post('/login', authUser);       

// Google
router.get('/google', googleLogin);
router.get('/google/callback', googleCallback);

// LinkedIn
router.get('/linkedin', linkedinLogin);
router.get('/linkedin/callback', linkedinCallback);

// OTP Login
router.post('/otp/send', sendOtp);
router.post('/otp/verify', verifyOtp);

// Reset Password
router.post('/reset/send', sendResetCode);
router.post('/reset', resetPassword);


// =======================
// 🔒 Protected Routes
// =======================
router.post('/logout', protect, logoutUser);
router.post('/change-password', protect, changePassword);
router.get('/check-status', protect, checkAuthStatus);

export default router;