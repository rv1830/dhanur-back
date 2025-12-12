// controllers/authController.js
import asyncHandler from 'express-async-handler';
import User from '../models/User.js';
import { setTokenCookie, invalidateSession } from '../utils/authUtils.js'; 
import { cookieOptions } from '../middleware/authMiddleware.js'; 
import { OAuth2Client } from 'google-auth-library';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import twilio from 'twilio'; // For OTP
import axios from 'axios'; // For LinkedIn OAuth calls

// =================================================================
// ⚙️ EXTERNAL SERVICE SETUP
// =================================================================

// Google OAuth Client setup (for token verification)
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Nodemailer Transport (For Email Reset/Verification)
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: process.env.SMTP_SECURE === 'true', 
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
});

// Twilio Client (For Phone OTP)
const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);


// =================================================================
// 1. BASIC EMAIL/PASSWORD AUTH
// =================================================================

// @desc    Register a new user
// @route   POST /api/auth/register
// @access  Public
export const registerUser = asyncHandler(async (req, res) => {
    const { email, password, userType } = req.body;
    if (!email || !password || !userType) {
        res.status(400); throw new Error('Please provide email, password, and userType.');
    }
    const userExists = await User.findOne({ email });
    if (userExists) {
        res.status(400); throw new Error('User already exists');
    }
    const user = await User.create({ email, password, userType, authProvider: 'LOCAL' });
    if (user) {
        setTokenCookie(res, user); 
        res.status(201).json({ _id: user._id, email: user.email, userType: user.userType });
    } else {
        res.status(400); throw new Error('Invalid user data');
    }
});

// @desc    Authenticate user & set token (Login)
// @route   POST /api/auth/login
// @access  Public
export const authUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user && (await user.matchPassword(password))) {
        setTokenCookie(res, user); 
        res.json({ _id: user._id, email: user.email, userType: user.userType });
    } else {
        res.status(401); throw new Error('Invalid email or password');
    }
});

// =================================================================
// 2. PROTECTED UTILITIES
// =================================================================

// @desc    Log out user / clear cookie
// @route   POST /api/auth/logout
// @access  Protected
export const logoutUser = asyncHandler(async (req, res) => {
    if (req.user) { await invalidateSession(req.user._id); }
    res.clearCookie('token', cookieOptions); 
    res.status(200).json({ message: 'Logged out successfully' });
});

// @desc    Change Password
// @route   POST /api/auth/change-password
// @access  Protected
export const changePassword = asyncHandler(async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const user = req.user;
    if (!oldPassword || !newPassword) { res.status(400); throw new Error('Please provide old and new password.'); }
    if (!await user.matchPassword(oldPassword)) { res.status(401); throw new Error('Invalid old password'); }
    user.password = newPassword; 
    await user.save();
    await invalidateSession(user._id);
    res.clearCookie('token', cookieOptions);
    res.status(200).json({ message: 'Password changed successfully. Please log in again.' });
});

// @desc    Check auth status
// @route   GET /api/auth/check-status
// @access  Protected
export const checkAuthStatus = asyncHandler(async (req, res) => {
    res.status(200).json({
        isAuthenticated: true,
        user: { _id: req.user._id, email: req.user.email, userType: req.user.userType },
    });
});


// =================================================================
// 3. SOCIAL AUTH (Google & LinkedIn)
// =================================================================

// ------------------------------------
// Google Login (POST - Token Verification Flow)
// ------------------------------------
// @desc    Authenticate/Register user using Google ID token
// @route   POST /api/auth/google
// @access  Public
export const googleLogin = (req, res) => {
    // 🛑 FIX: Use the Redirect URI from .env
    const redirectUri = process.env.GOOGLE_REDIRECT_URI; 
    const scopes = 'openid profile email'; 
    const state = crypto.randomBytes(16).toString('hex');

    const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
        `client_id=${process.env.GOOGLE_CLIENT_ID}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&response_type=code` +
        `&scope=${encodeURIComponent(scopes)}` +
        `&access_type=offline` + // CRITICAL: To get the Refresh Token
        `&state=${state}`;
    
    // In a real app, save 'state' in session/cookie to verify later
    res.redirect(authUrl);
};

// 🛑 FIX 2: Implement Token Exchange/User Creation in googleCallback (501 Placeholder ko hatao)
// @desc    Handles Google OAuth callback, exchanges code for token
// @route   GET /api/auth/google/callback
// @access  Public
export const googleCallback = asyncHandler(async (req, res) => {
    const { code, state } = req.query;

    if (!code || !state) {
        res.status(400); throw new Error('OAuth flow error: Missing code or state.');
    }
    // TODO: Add state verification here

    // 1. Exchange authorization code for Access Token and Refresh Token
    const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', null, {
        params: {
            grant_type: 'authorization_code',
            code,
            redirect_uri: process.env.GOOGLE_REDIRECT_URI,
            client_id: process.env.GOOGLE_CLIENT_ID,
            client_secret: process.env.GOOGLE_CLIENT_SECRET,
        },
    });

    const { access_token, refresh_token } = tokenResponse.data;

    // 2. Fetch user profile (ID and Email) using the Access Token
    // We use the People API for standard Google profile/email info
    const profileResponse = await axios.get('https://www.googleapis.com/oauth2/v3/userinfo', {
        headers: { Authorization: `Bearer ${access_token}` }
    });
    
    const { sub: googleId, email, given_name } = profileResponse.data; // sub is the unique Google ID
    
    // NOTE: userType is not available from Google, default or prompt later
    const assumedUserType = 'BRAND'; 

    // 3. Find or Create User
    let user = await User.findOne({ $or: [{ googleId }, { email }] });
    
    if (!user) {
        // Create user (no password needed)
        user = await User.create({ email, googleId, userType: assumedUserType, authProvider: 'GOOGLE' });
    } else if (!user.googleId) {
        // Link existing email account to Google ID
        user.googleId = googleId;
        user.authProvider = 'GOOGLE';
        await user.save();
    }
    
    // 4. Set token and redirect
    setTokenCookie(res, user);

    // Redirect to frontend success page
    res.redirect(`${process.env.FRONTEND_URL}/?token_set=true`); 
});


// ------------------------------------
// LinkedIn Login (GET - Redirection Flow Start)
// ------------------------------------
// @desc    Redirects user to LinkedIn OAuth page
// @route   GET /api/auth/linkedin
// @access  Public
export const linkedinLogin = (req, res) => {
    const scope = encodeURIComponent('r_liteprofile r_emailaddress');
    const redirectUri = encodeURIComponent(process.env.LINKEDIN_REDIRECT_URI);
    const state = crypto.randomBytes(16).toString('hex'); // Prevent CSRF

    const authUrl = `https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=${process.env.LINKEDIN_CLIENT_ID}&redirect_uri=${redirectUri}&state=${state}&scope=${scope}`;
    
    // In a real app, save 'state' in session/cookie to verify later
    res.redirect(authUrl);
};

// @desc    Handles LinkedIn OAuth callback, exchanges code for token
// @route   GET /api/auth/linkedin/callback
// @access  Public
export const linkedinCallback = asyncHandler(async (req, res) => {
    const { code, state } = req.query;

    if (!code || !state) {
        res.status(400); throw new Error('OAuth flow error: Missing code or state.');
    }
    // TODO: Add state verification against session/cookie here

    // 1. Exchange authorization code for access token
    const tokenResponse = await axios.post('https://www.linkedin.com/oauth/v2/accessToken', null, {
        params: {
            grant_type: 'authorization_code',
            code,
            redirect_uri: process.env.LINKEDIN_REDIRECT_URI,
            client_id: process.env.LINKEDIN_CLIENT_ID,
            client_secret: process.env.LINKEDIN_CLIENT_SECRET,
        },
    });

    const accessToken = tokenResponse.data.access_token;

    // 2. Fetch user profile (ID)
    const profileResponse = await axios.get('https://api.linkedin.com/v2/userinfo', {
        headers: { Authorization: `Bearer ${accessToken}` }
    });
    
    const { sub: linkedinId, email, userType } = profileResponse.data; // LinkedIn ID is 'sub'
    
    // NOTE: LinkedIn API might not return userType. Assuming you fetch/prompt it later.
    const assumedUserType = 'BRAND'; // Placeholder or get from context

    // 3. Find or Create User
    let user = await User.findOne({ $or: [{ linkedinId }, { email }] });
    
    if (!user) {
        user = await User.create({ email, linkedinId, userType: assumedUserType, authProvider: 'LINKEDIN' });
    } else if (!user.linkedinId) {
        user.linkedinId = linkedinId;
        user.authProvider = 'LINKEDIN';
        await user.save();
    }
    
    // 4. Set token and redirect (or send success JSON)
    setTokenCookie(res, user);

    // Redirect to frontend success page after successful login
    res.redirect(`${process.env.FRONTEND_URL}/?token_set=true`); 
});


// =================================================================
// 4. OTP LOGIN (Phone Number)
// =================================================================

// @desc    Send OTP to the user's phone number
// @route   POST /api/auth/otp/send
// @access  Public
export const sendOtp = asyncHandler(async (req, res) => {
    const { phoneNumber } = req.body;
    
    if (!phoneNumber) {
        res.status(400); throw new Error('Phone number is required.');
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
    const otpExpiry = Date.now() + 5 * 60 * 1000; // 5 minutes

    let user = await User.findOne({ phoneNumber });
    if (!user) {
        // If user doesn't exist, create a temporary/unverified user entry
        user = await User.create({ 
            phoneNumber, 
            userType: 'BRAND', // Default userType if registering via OTP
            authProvider: 'PHONE' 
        });
    }

    // Save OTP and expiry
    user.verificationCode = otp;
    user.codeExpiry = otpExpiry;
    await user.save({ validateBeforeSave: false });

    // Send OTP via Twilio
    await twilioClient.messages.create({
        body: `Your Dhanur verification code is ${otp}. It expires in 5 minutes.`,
        from: process.env.TWILIO_PHONE_NUMBER, // Your Twilio number
        to: phoneNumber,
    });

    res.json({ message: 'OTP sent to your phone number.' });
});

// @desc    Verify OTP and log the user in
// @route   POST /api/auth/otp/verify
// @access  Public
export const verifyOtp = asyncHandler(async (req, res) => {
    const { phoneNumber, otp } = req.body;

    const user = await User.findOne({ phoneNumber });

    if (!user || 
        user.verificationCode !== otp || 
        user.codeExpiry < Date.now()) 
    {
        res.status(401);
        throw new Error('Invalid or expired OTP.');
    }

    // Clear OTP fields and update provider
    user.verificationCode = undefined;
    user.codeExpiry = undefined;
    user.authProvider = 'PHONE'; 
    await user.save({ validateBeforeSave: false });

    // Log the user in
    setTokenCookie(res, user); 
    res.status(200).json({ _id: user._id, phoneNumber: user.phoneNumber, userType: user.userType, message: 'Login successful via OTP.' });
});


// =================================================================
// 5. PASSWORD RESET (Email)
// =================================================================

// @desc    Send password reset code to user email
// @route   POST /api/auth/reset/send
// @access  Public
export const sendResetCode = asyncHandler(async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
        // Send success regardless, to prevent email enumeration attacks
        return res.json({ message: 'If a matching email was found, a reset code has been sent.' });
    }
    
    // Generate token and expiry
    const resetCode = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit code
    const codeExpiry = Date.now() + 10 * 60 * 1000; // 10 minutes

    user.verificationCode = resetCode;
    user.codeExpiry = codeExpiry;
    await user.save({ validateBeforeSave: false });

    // Send email
    try {
        await transporter.sendMail({
            to: user.email,
            subject: 'Password Reset Code for Dhanur',
            html: `Your password reset code is <strong>${resetCode}</strong>. It expires in 10 minutes.`,
        });

        res.json({ message: 'Password reset code sent to your email.' });
    } catch (error) {
        console.error("Email send error:", error);
        res.status(500);
        throw new Error('Error sending reset code email.');
    }
});

// @desc    Reset password using the code
// @route   POST /api/auth/reset
// @access  Public
export const resetPassword = asyncHandler(async (req, res) => {
    const { email, resetCode, newPassword } = req.body;

    const user = await User.findOne({ email });

    if (!user || 
        user.verificationCode !== resetCode || 
        user.codeExpiry < Date.now()) 
    {
        res.status(400);
        throw new Error('Invalid or expired reset code.');
    }
    
    if (!newPassword || newPassword.length < 6) {
        res.status(400);
        throw new Error('New password must be at least 6 characters.');
    }

    // Update password and clear reset fields
    user.password = newPassword; 
    user.verificationCode = undefined;
    user.codeExpiry = undefined;
    await user.save(); // pre-save hook will hash the password

    // Invalidate old sessions/tokens (security)
    await invalidateSession(user._id);
    
    res.status(200).json({ message: 'Password has been reset successfully. Please login.' });
});