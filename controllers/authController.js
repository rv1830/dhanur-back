// --- controllers/authController.js (UPDATED CODE) ---

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
// ⚙️ EXTERNAL SERVICE SETUP (unchanged)
// =================================================================
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
// ... (transporter and twilioClient setup) ...

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

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

// =================================================================
// 1. BASIC EMAIL/PASSWORD AUTH
// =================================================================

// 🔥 registerUser (NO CHANGE IN LOGIC: Always redirects to onboarding)
export const registerUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        res.status(400); 
        throw new Error('Please provide email and password.');
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
        userType: null, // New users start with null userType
        onboardingComplete: false,
        authProvider: 'LOCAL' 
    });
    
    setTokenCookie(res, user); 
    res.status(201).json({ 
        _id: user._id, 
        email: user.email, 
        userType: user.userType,
        onboardingComplete: user.onboardingComplete, 
        authProvider: user.authProvider,
        message: 'Registration successful. Redirecting to user type selection.',
        redirectTo: '/select-usertype' // Frontend uses this flag
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
        
        // 🚨 CRITICAL FIX: Only redirect to onboarding if userType is explicitly NULL.
        if (user.userType === null) {
            return res.json({ 
                _id: user._id, 
                email: user.email, 
                userType: user.userType,
                onboardingComplete: user.onboardingComplete,
                authProvider: user.authProvider,
                message: 'Login successful. Redirecting to onboarding.',
                redirectTo: '/select-usertype'
            });
        }

        // If userType is not null (i.e., user is old/onboarded), send them to dashboard.
        const dashboardPath = user.userType === 'BRAND' ? '/dashboard/brand' : 
                             user.userType === 'INFLUENCER' ? '/dashboard/influencer' : '/dashboard'; // Fallback
        
        res.json({ 
            _id: user._id, 
            email: user.email, 
            userType: user.userType,
            onboardingComplete: user.onboardingComplete,
            authProvider: user.authProvider,
            message: 'Login successful',
            redirectTo: dashboardPath
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

// logoutUser, changePassword, checkAuthStatus functions remain the same.

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
            onboardingComplete: req.user.onboardingComplete, // Onboarding status return करें
            authProvider: req.user.authProvider
        },
    });
});

// =================================================================
// 3. GOOGLE AUTH - SINGLE CALLBACK WITH STATE
// =================================================================

// 🔥 MODIFIED: googleSignup अब userType को query से नहीं लेगा, बल्कि default state 'signup' ही रखेगा
export const googleSignup = (req, res) => {
    const redirectUri = process.env.GOOGLE_REDIRECT_URI;
    const scopes = 'openid profile email'; 
    // State format: "signup:randomhex"
    const state = `signup:${crypto.randomBytes(8).toString('hex')}`;

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

// 🔥 MODIFIED: googleCallback अब userType के बजाय Onboarding status के आधार पर रीडायरेक्ट करेगा
export const googleCallback = asyncHandler(async (req, res) => {
    const { code, state } = req.query;

    if (!code || !state) {
        return res.redirect(`${FRONTEND_URL}/login?error=oauth_flow_error`);
    }

    const stateParts = state.toString().split(':');
    const action = stateParts[0];
    
    const redirectUri = process.env.GOOGLE_REDIRECT_URI;

    let user;
    try {
        // ... (Token exchange and profile fetching logic) ...
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
            if (user) {
                return res.redirect(`${FRONTEND_URL}/login?error=user_already_exists`);
            }

            user = await User.create({ 
                email: email.toLowerCase().trim(), 
                name: name || email.split('@')[0],
                googleId, 
                userType: null, 
                onboardingComplete: false, 
                authProvider: 'GOOGLE',
                profilePicture: picture
            });
            
        } else {
            if (!user) {
                return res.redirect(`${FRONTEND_URL}/signup?error=no_account_found`);
            }

            if (!user.googleId) {
                user.googleId = googleId;
                user.authProvider = 'GOOGLE';
                if (!user.name) user.name = name;
                if (!user.profilePicture) user.profilePicture = picture;
                await user.save();
            }
        }
        
        // **--- 🎉 ऑथेंटिकेशन सफल: रीडायरेक्ट लॉजिक 🎉 ---**
        setTokenCookie(res, user);
        
        // 🚨 CRITICAL FIX: Only redirect to onboarding if userType is explicitly NULL.
        if (user.userType === null) {
            return res.redirect(`${FRONTEND_URL}/select-usertype`); 
        }

        // If userType is set, redirect to their dashboard
        let dashboardPath = user.userType === 'BRAND' ? '/dashboard/brand' : 
                             user.userType === 'INFLUENCER' ? '/dashboard/influencer' : '/dashboard'; // Fallback
        
        return res.redirect(`${FRONTEND_URL}${dashboardPath}`);

    } catch (error) {
        console.error("Google Callback Error:", error);
        return res.redirect(`${FRONTEND_URL}/login?error=server_error`);
    }
});

// =================================================================
// 4. LINKEDIN AUTH - SINGLE CALLBACK WITH STATE
// =================================================================

// 🔥 MODIFIED: linkedinSignup अब userType को query से नहीं लेगा, बल्कि default state 'signup' ही रखेगा
export const linkedinSignup = (req, res) => {
    const scope = encodeURIComponent('openid profile email');
    const redirectUri = encodeURIComponent(process.env.LINKEDIN_REDIRECT_URI);
    const state = `signup:${crypto.randomBytes(8).toString('hex')}`; // userType हटा दिया

    const authUrl = `https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=${process.env.LINKEDIN_CLIENT_ID}&redirect_uri=${redirectUri}&state=${state}&scope=${scope}`;
    res.redirect(authUrl);
};

export const linkedinLogin = (req, res) => {
    const scope = encodeURIComponent('openid profile email');
    const redirectUri = encodeURIComponent(process.env.LINKEDIN_REDIRECT_URI);
    const state = `login:${crypto.randomBytes(16).toString('hex')}`;

    const authUrl = `https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=${process.env.LINKEDIN_CLIENT_ID}&redirect_uri=${redirectUri}&state=${state}&scope=${scope}`;
    res.redirect(authUrl);
};

// 🔥 MODIFIED: linkedinCallback अब userType के बजाय Onboarding status के आधार पर रीडायरेक्ट करेगा
export const linkedinCallback = asyncHandler(async (req, res) => {
    const { code, state } = req.query;

    if (!code || !state) {
        return res.redirect(`${FRONTEND_URL}/login?error=oauth_flow_error`);
    }

    const stateParts = state.toString().split(':');
    const action = stateParts[0];
    
    const redirectUri = process.env.LINKEDIN_REDIRECT_URI;
    let user;

    try {
        // ... (Token exchange and profile fetching logic) ...
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
                userType: null, 
                onboardingComplete: false, 
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
        setTokenCookie(res, user);
        
        // 🚨 CRITICAL FIX: Only redirect to onboarding if userType is explicitly NULL.
        if (user.userType === null) {
            return res.redirect(`${FRONTEND_URL}/select-usertype`); 
        }

        // If userType is set, redirect to their dashboard
        let dashboardPath = user.userType === 'BRAND' ? '/dashboard/brand' : 
                             user.userType === 'INFLUENCER' ? '/dashboard/influencer' : '/dashboard'; // Fallback
        
        return res.redirect(`${FRONTEND_URL}${dashboardPath}`);

    } catch (error) {
        console.error("LinkedIn Callback Error:", error);
        return res.redirect(`${FRONTEND_URL}/login?error=server_error`);
    }
});

// =================================================================
// 5. OTP LOGIN (Phone Number)
// =================================================================

// 🔥 MODIFIED: OTP flow में भी default userType को null सेट करें
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
            userType: null, // 👈 Null set किया
            onboardingComplete: false, // 👈 False set किया
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

// 🔥 MODIFIED: OTP Verify के बाद Onboarding check करें
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
    
    // 🚨 CRITICAL FIX: Add redirectTo field to guide frontend
    let redirectTo = null;
    if (user.userType === null) {
         redirectTo = '/select-usertype';
    } else {
         redirectTo = user.userType === 'BRAND' ? '/dashboard/brand' : 
                      user.userType === 'INFLUENCER' ? '/dashboard/influencer' : '/dashboard';
    }
    
    res.status(200).json({ 
        _id: user._id, 
        phoneNumber: user.phoneNumber, 
        userType: user.userType,
        onboardingComplete: user.onboardingComplete,
        authProvider: user.authProvider,
        message: 'Login successful via OTP.',
        redirectTo: redirectTo
    });
});

// =================================================================
// 6. PASSWORD RESET (Email)
// =================================================================

// sendResetCode, resetPassword functions remain the same.

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


// =================================================================
// 7. USERTYPE SELECTION (New Onboarding Step)
// =================================================================

export const selectUserType = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    const { userType } = req.body; // Expects 'BRAND' or 'INFLUENCER'

    // 1. Validation
    const validTypes = ['BRAND', 'INFLUENCER'];
    if (!userType || !validTypes.includes(userType)) {
        res.status(400); 
        throw new Error('Invalid user type. Must be BRAND or INFLUENCER.');
    }

    const user = req.user; 

    // 2. 🛡️ CONFLICT CHECK (Strict Rule: Mutually Exclusive)
    if (user.userType && user.userType !== userType) {
        res.status(400);
        throw new Error(`Conflict detected: You are already registered as an ${user.userType}. A user cannot be both BRAND and INFLUENCER.`);
    }

    // 3. User को अपडेट करें (केवल अगर userType null है, यानी पहला चयन)
    if (!user.userType) {
        user.userType = userType;
        user.onboardingComplete = true; 
        await user.save();
        
        // 4. Session Invalid / New Token (Security Step: Token में updated userType होगा)
        await invalidateSession(userId); 
        setTokenCookie(res, user); 
    } else if (user.userType === userType && !user.onboardingComplete) {
        // यह केस तब हो सकता है जब कोई userType पहले ही DB में सेट हो लेकिन onboardingComplete false हो
        user.onboardingComplete = true;
        await user.save();
        await invalidateSession(userId); 
        setTokenCookie(res, user); 
    }
    
    // 5. Success Response
    let dashboardPath = user.userType === 'BRAND' ? '/dashboard/brand' : '/dashboard/influencer';
    
    res.status(200).json({
        message: `User type set to ${user.userType}. Onboarding complete.`,
        user: { 
            _id: user._id, 
            email: user.email, 
            userType: user.userType,
            onboardingComplete: user.onboardingComplete
        },
        redirectTo: dashboardPath
    });
});