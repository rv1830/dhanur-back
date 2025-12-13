import asyncHandler from 'express-async-handler';
import bcrypt from 'bcryptjs';
import User from '../models/User.js';
import { setTokenCookie, invalidateSession } from '../utils/authUtils.js'; 
import { cookieOptions } from '../middleware/authMiddleware.js'; 
import { OAuth2Client } from 'google-auth-library';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import twilio from 'twilio';
import axios from 'axios';

// =================================================================
// ⚙️ EXTERNAL SERVICE SETUP
// =================================================================
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: process.env.SMTP_SECURE === 'true', 
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
});

const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

// क्लाइंट बेस URL को .env से लें या डिफ़ॉल्ट दें
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

// =================================================================
// 1. BASIC EMAIL/PASSWORD AUTH
// =================================================================

export const registerUser = asyncHandler(async (req, res) => {
    const { email, password, userType } = req.body;
    if (!email || !password || !userType) {
        res.status(400); 
        throw new Error('Please provide email, password, and userType.');
    }
    
    const userExists = await User.findOne({ email: email.toLowerCase().trim() });
    if (userExists) {
        res.status(400); 
        throw new Error('User already exists');
    }
    
    const hashedPassword = await bcrypt.hash(password, 12);
    const user = await User.create({ 
        email: email.toLowerCase().trim(), 
        password: hashedPassword, 
        userType, 
        authProvider: 'LOCAL' 
    });
    
    setTokenCookie(res, user); 
    res.status(201).json({ 
        _id: user._id, 
        email: user.email, 
        userType: user.userType,
        authProvider: user.authProvider,
        message: 'Registration successful'
    });
});

export const authUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    console.log('🔍 Login attempt:', email);
    
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user || !user.password) {
        console.log('❌ User not found');
        res.status(401); 
        throw new Error('Invalid email or password');
    }
    
    console.log('✅ Hash length:', user.password.length);
    const isMatch = await user.matchPassword(password);
    console.log('🔑 Password match:', isMatch);
    
    if (isMatch) {
        setTokenCookie(res, user); 
        res.json({ 
            _id: user._id, 
            email: user.email, 
            userType: user.userType,
            authProvider: user.authProvider,
            message: 'Login successful'
        });
    } else {
        console.log('❌ Password mismatch');
        res.status(401); 
        throw new Error('Invalid email or password');
    }
});

// =================================================================
// 2. PROTECTED UTILITIES
// =================================================================

export const logoutUser = asyncHandler(async (req, res) => {
    if (req.user) { await invalidateSession(req.user._id); }
    res.clearCookie('token', cookieOptions); 
    res.status(200).json({ message: 'Logged out successfully' });
});

export const changePassword = asyncHandler(async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const user = req.user;
    
    if (!oldPassword || !newPassword) { 
        res.status(400); 
        throw new Error('Please provide old and new password.'); 
    }
    
    if (!await user.matchPassword(oldPassword)) { 
        res.status(401); 
        throw new Error('Invalid old password'); 
    }
    
    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();
    await invalidateSession(user._id);
    res.clearCookie('token', cookieOptions);
    res.status(200).json({ message: 'Password changed successfully. Please log in again.' });
});

export const checkAuthStatus = asyncHandler(async (req, res) => {
    res.status(200).json({
        isAuthenticated: true,
        user: { 
            _id: req.user._id, 
            email: req.user.email, 
            name: req.user.name,
            userType: req.user.userType,
            authProvider: req.user.authProvider
        },
    });
});

// =================================================================
// 3. GOOGLE AUTH - SINGLE CALLBACK WITH STATE
// =================================================================

// Google Signup - encodes userType in state
export const googleSignup = (req, res) => {
    const { userType } = req.query;
    
    if (!userType || !['BRAND', 'INFLUENCER'].includes(userType)) {
        res.status(400);
        throw new Error('Invalid or missing userType. Must be BRAND or INFLUENCER.');
    }
    
    const redirectUri = process.env.GOOGLE_REDIRECT_URI;
    const scopes = 'openid profile email'; 
    // State format: "signup:BRAND:randomhex" or "signup:INFLUENCER:randomhex"
    const state = `signup:${userType}:${crypto.randomBytes(8).toString('hex')}`;

    const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
        `client_id=${process.env.GOOGLE_CLIENT_ID}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&response_type=code` +
        `&scope=${encodeURIComponent(scopes)}` +
        `&access_type=offline` +
        `&state=${state}` +
        `&prompt=consent`;
    
    res.redirect(authUrl);
};

// Google Login - encodes login in state
export const googleLogin = (req, res) => {
    const redirectUri = process.env.GOOGLE_REDIRECT_URI;
    const scopes = 'openid profile email'; 
    // State format: "login:randomhex"
    const state = `login:${crypto.randomBytes(16).toString('hex')}`;

    const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
        `client_id=${process.env.GOOGLE_CLIENT_ID}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&response_type=code` +
        `&scope=${encodeURIComponent(scopes)}` +
        `&access_type=offline` +
        `&state=${state}`;
    
    res.redirect(authUrl);
};

// Google Unified Callback - handles both signup and login
export const googleCallback = asyncHandler(async (req, res) => {
    const { code, state } = req.query;

    if (!code || !state) {
        // अगर कोड या स्टेट मिसिंग है, तो लॉगिन पेज पर एरर के साथ रीडायरेक्ट करें
        return res.redirect(`${FRONTEND_URL}/login?error=oauth_flow_error`);
    }

    // Parse state: "signup:BRAND:abc123" or "login:xyz789"
    const stateParts = state.toString().split(':');
    const action = stateParts[0]; // "signup" or "login"
    const userType = action === 'signup' ? stateParts[1] : null;
    
    if (action === 'signup' && !userType) {
        return res.redirect(`${FRONTEND_URL}/login?error=invalid_signup_state`);
    }

    const redirectUri = process.env.GOOGLE_REDIRECT_URI;

    let user;
    try {
        const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', null, {
            params: {
                grant_type: 'authorization_code',
                code,
                redirect_uri: redirectUri,
                client_id: process.env.GOOGLE_CLIENT_ID,
                client_secret: process.env.GOOGLE_CLIENT_SECRET,
            },
        });

        const { access_token } = tokenResponse.data;

        const profileResponse = await axios.get('https://www.googleapis.com/oauth2/v3/userinfo', {
            headers: { Authorization: `Bearer ${access_token}` }
        });
        
        const { sub: googleId, email, name, picture } = profileResponse.data;

        user = await User.findOne({ $or: [{ googleId }, { email: email.toLowerCase().trim() }] });
        
        if (action === 'signup') {
            // SIGNUP FLOW
            if (user) {
                // User पहले से मौजूद है, लॉगिन पेज पर भेजें
                return res.redirect(`${FRONTEND_URL}/login?error=user_already_exists`);
            }

            user = await User.create({ 
                email: email.toLowerCase().trim(), 
                name: name || email.split('@')[0],
                googleId, 
                userType, 
                authProvider: 'GOOGLE',
                profilePicture: picture
            });
            
        } else {
            // LOGIN FLOW
            if (!user) {
                // अकाउंट नहीं मिला, साइनअप पेज पर भेजें
                return res.redirect(`${FRONTEND_URL}/signup?error=no_account_found`);
            }

            if (!user.googleId) {
                // लोकल/दूसरे अकाउंट को Google से लिंक करें
                user.googleId = googleId;
                user.authProvider = 'GOOGLE';
                if (!user.name) user.name = name;
                if (!user.profilePicture) user.profilePicture = picture;
                await user.save();
            }
        }
        
        // **--- 🎉 ऑथेंटिकेशन सफल: रीडायरेक्ट लॉजिक 🎉 ---**
        
        // 1. HTTP-only कुकी सेट करें
        setTokenCookie(res, user);
        
        // 2. UserType के आधार पर पाथ चुनें
        let dashboardPath = '/dashboard'; // Default Fallback
        
        if (user.userType === 'BRAND') {
            dashboardPath = '/dashboard/brand';
        } else if (user.userType === 'INFLUENCER') {
            dashboardPath = '/dashboard/influencer';
        }
        
        // 3. क्लाइंट को सही डैशबोर्ड पर रीडायरेक्ट करें
        return res.redirect(`${FRONTEND_URL}${dashboardPath}`);

    } catch (error) {
        console.error("Google Callback Error:", error);
        // किसी भी गंभीर त्रुटि पर लॉगिन पेज पर वापस भेजें
        return res.redirect(`${FRONTEND_URL}/login?error=server_error`);
    }
});

// =================================================================
// 4. LINKEDIN AUTH - SINGLE CALLBACK WITH STATE
// =================================================================

// LinkedIn Signup - encodes userType in state
export const linkedinSignup = (req, res) => {
    const { userType } = req.query;
    
    if (!userType || !['BRAND', 'INFLUENCER'].includes(userType)) {
        res.status(400);
        throw new Error('Invalid or missing userType. Must be BRAND or INFLUENCER.');
    }
    
    const scope = encodeURIComponent('openid profile email');
    const redirectUri = encodeURIComponent(process.env.LINKEDIN_REDIRECT_URI);
    const state = `signup:${userType}:${crypto.randomBytes(8).toString('hex')}`;

    const authUrl = `https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=${process.env.LINKEDIN_CLIENT_ID}&redirect_uri=${redirectUri}&state=${state}&scope=${scope}`;
    res.redirect(authUrl);
};

// LinkedIn Login - encodes login in state
export const linkedinLogin = (req, res) => {
    const scope = encodeURIComponent('openid profile email');
    const redirectUri = encodeURIComponent(process.env.LINKEDIN_REDIRECT_URI);
    const state = `login:${crypto.randomBytes(16).toString('hex')}`;

    const authUrl = `https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=${process.env.LINKEDIN_CLIENT_ID}&redirect_uri=${redirectUri}&state=${state}&scope=${scope}`;
    res.redirect(authUrl);
};

// LinkedIn Unified Callback - handles both signup and login
export const linkedinCallback = asyncHandler(async (req, res) => {
    const { code, state } = req.query;

    if (!code || !state) {
        return res.redirect(`${FRONTEND_URL}/login?error=oauth_flow_error`);
    }

    const stateParts = state.toString().split(':');
    const action = stateParts[0];
    const userType = action === 'signup' ? stateParts[1] : null;
    
    if (action === 'signup' && !userType) {
        return res.redirect(`${FRONTEND_URL}/login?error=invalid_signup_state`);
    }

    const redirectUri = process.env.LINKEDIN_REDIRECT_URI;
    let user;

    try {
        const tokenResponse = await axios.post('https://www.linkedin.com/oauth/v2/accessToken', null, {
            params: {
                grant_type: 'authorization_code',
                code,
                redirect_uri: redirectUri,
                client_id: process.env.LINKEDIN_CLIENT_ID,
                client_secret: process.env.LINKEDIN_CLIENT_SECRET,
            },
        });

        const accessToken = tokenResponse.data.access_token;

        const profileResponse = await axios.get('https://api.linkedin.com/v2/userinfo', {
            headers: { Authorization: `Bearer ${accessToken}` }
        });
        
        const { sub: linkedinId, email, name, picture } = profileResponse.data;

        user = await User.findOne({ $or: [{ linkedinId }, { email: email.toLowerCase().trim() }] });
        
        if (action === 'signup') {
            if (user) {
                return res.redirect(`${FRONTEND_URL}/login?error=user_already_exists`);
            }

            user = await User.create({ 
                email: email.toLowerCase().trim(), 
                name: name || email.split('@')[0],
                linkedinId, 
                userType, 
                authProvider: 'LINKEDIN',
                profilePicture: picture
            });
            
        } else {
            if (!user) {
                return res.redirect(`${FRONTEND_URL}/signup?error=no_account_found`);
            }

            if (!user.linkedinId) {
                user.linkedinId = linkedinId;
                user.authProvider = 'LINKEDIN';
                if (!user.name) user.name = name;
                if (!user.profilePicture) user.profilePicture = picture;
                await user.save();
            }
        }
        
        // **--- 🎉 ऑथेंटिकेशन सफल: रीडायरेक्ट लॉजिक 🎉 ---**
        
        // 1. HTTP-only कुकी सेट करें
        setTokenCookie(res, user);
        
        // 2. UserType के आधार पर पाथ चुनें
        let dashboardPath = '/dashboard'; // Default Fallback
        
        if (user.userType === 'BRAND') {
            dashboardPath = '/dashboard/brand';
        } else if (user.userType === 'INFLUENCER') {
            dashboardPath = '/dashboard/influencer';
        }
        
        // 3. क्लाइंट को सही डैशबोर्ड पर रीडायरेक्ट करें
        return res.redirect(`${FRONTEND_URL}${dashboardPath}`);

    } catch (error) {
        console.error("LinkedIn Callback Error:", error);
        return res.redirect(`${FRONTEND_URL}/login?error=server_error`);
    }
});

// =================================================================
// 5. OTP LOGIN (Phone Number)
// =================================================================

export const sendOtp = asyncHandler(async (req, res) => {
    const { phoneNumber } = req.body;
    
    if (!phoneNumber) {
        res.status(400); 
        throw new Error('Phone number is required.');
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiry = Date.now() + 5 * 60 * 1000;

    let user = await User.findOne({ phoneNumber });
    if (!user) {
        user = await User.create({ 
            phoneNumber, 
            userType: 'BRAND', // Default user type for new phone user
            authProvider: 'PHONE' 
        });
    }

    user.verificationCode = otp;
    user.codeExpiry = otpExpiry;
    await user.save({ validateBeforeSave: false });

    await twilioClient.messages.create({
        body: `Your Dhanur verification code is ${otp}. It expires in 5 minutes.`,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: phoneNumber,
    });

    res.json({ message: 'OTP sent to your phone number.' });
});

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

    user.verificationCode = undefined;
    user.codeExpiry = undefined;
    user.authProvider = 'PHONE'; 
    await user.save({ validateBeforeSave: false });

    setTokenCookie(res, user); 
    res.status(200).json({ 
        _id: user._id, 
        phoneNumber: user.phoneNumber, 
        userType: user.userType,
        authProvider: user.authProvider,
        message: 'Login successful via OTP.' 
    });
});

// =================================================================
// 6. PASSWORD RESET (Email)
// =================================================================

export const sendResetCode = asyncHandler(async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email: email.toLowerCase().trim() });

    if (!user) {
        return res.json({ message: 'If a matching email was found, a reset code has been sent.' });
    }
    
    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
    const codeExpiry = Date.now() + 10 * 60 * 1000;

    user.verificationCode = resetCode;
    user.codeExpiry = codeExpiry;
    await user.save({ validateBeforeSave: false });

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

export const resetPassword = asyncHandler(async (req, res) => {
    const { email, resetCode, newPassword } = req.body;
    const user = await User.findOne({ email: email.toLowerCase().trim() });

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

    user.password = await bcrypt.hash(newPassword, 12);
    user.verificationCode = undefined;
    user.codeExpiry = undefined;
    await user.save();
    
    await invalidateSession(user._id);
    
    res.status(200).json({ message: 'Password has been reset successfully. Please login.' });
});

// --- authController.js (New Function: selectUserType) ---
// Note: आपको इसे routes/auth.js में protect middleware के साथ जोड़ना होगा।

export const selectUserType = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    const { userType } = req.body; // Expects 'BRAND' or 'INFLUENCER'

    if (!userType || !['BRAND', 'INFLUENCER'].includes(userType)) {
        res.status(400); 
        throw new Error('Invalid user type. Must be BRAND or INFLUENCER.');
    }

    const user = req.user; // User object from protect middleware

    // **🛡️ Conflict Check (Strict Rule)**
    if (user.userType && user.userType !== userType) {
        // If they already chose one type, and are trying to select the other
        res.status(400);
        throw new Error(`Conflict detected: You are already registered as an ${user.userType}. You cannot be both.`);
    }

    // 1. User को अपडेट करें
    user.userType = userType;
    user.onboardingComplete = true; // Onboarding complete set करें
    await user.save();
    
    // 2. Session Invalid / New Token
    await invalidateSession(userId); // पुराने टोकन को अमान्य करें
    setTokenCookie(res, user); // नया टोकन दें
    
    // 3. Success Response
    let dashboardPath = userType === 'BRAND' ? '/dashboard/brand' : '/dashboard/influencer';
    
    res.status(200).json({
        message: `User type set to ${userType}.`,
        user: { 
            _id: user._id, 
            email: user.email, 
            userType: user.userType 
        },
        redirectTo: dashboardPath // Frontend इस पाथ का उपयोग कर सकता है
    });
});