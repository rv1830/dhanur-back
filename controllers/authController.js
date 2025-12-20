// --- controllers/authController.js (UPDATED with Dynamic Dashboard Paths) ---

import asyncHandler from 'express-async-handler';
import bcrypt from 'bcryptjs';
import User from '../models/User.js';
import Brand from '../models/Brand.js'; // ✅ IMPORT ADDED FOR ID LOOKUP
import { setTokenCookie, invalidateSession } from '../utils/authUtils.js'; 
import { cookieOptions } from '../middleware/authMiddleware.js'; 
import { OAuth2Client } from 'google-auth-library';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import axios from 'axios';
import { getMetaLongLivedToken } from '../services/metaService.js'; 

// =================================================================
// ⚙️ EXTERNAL SERVICE SETUP 
// =================================================================
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const META_BASE_URL_OAUTH = 'https://www.facebook.com/v18.0/dialog/oauth';

const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false, 
    auth: {
        user: 'outreach@linkup.capital', 
        pass: 'dwxi ieuy yhmq lixf', 
    },
});

transporter.verify((error, success) => {
    if (error) {
        console.error("❌ SMTP Transporter Verification Failed:", error.message);
    } else {
        console.log("✅ SMTP Transporter Ready. (Using Hardcoded Auth)");
    }
});

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

// =================================================================
// 🛠️ HELPER: GET DASHBOARD PATH
// =================================================================
// Decides where to send the user based on Type and Brand Membership
const getDashboardPath = async (user) => {
    // 1. Influencer -> Direct Dashboard
    if (user.userType === 'INFLUENCER') {
        return '/dashboard'; 
    } 
    
    // 2. Brand -> Dashboard + Brand ID
    if (user.userType === 'BRAND') {
        // Find which brand this user belongs to
        const userBrand = await Brand.findOne({ 'members.user': user._id }).select('bid');
        
        if (userBrand) {
            // ✅ Dynamic URL: /dashboard/br_12345
            return `/dashboard/${userBrand.bid}`; 
        } else {
            // User is BRAND type but hasn't created/joined a brand yet
            return '/onboarding'; 
        }
    }
    
    return '/select-usertype'; // Fallback
};

// =================================================================
// 1. BASIC EMAIL/PASSWORD AUTH
// =================================================================

export const registerUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    
    // 1. Validation (8 characters password check)
    if (!email || !password) {
        res.status(400); 
        throw new Error('Please provide email and password.');
    }

    if (password.length < 8) {
        res.status(400);
        throw new Error('Password must be at least 8 characters long.');
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
        userType: null, // ✅ Explicitly Null
        profileComplete: false, 
        onboardingComplete: false,
        authProvider: 'LOCAL' 
    });
    
    setTokenCookie(res, user); 
    res.status(201).json({ 
        uid: user.uid,
        email: user.email, 
        userType: user.userType,
        profileComplete: user.profileComplete,
        onboardingComplete: user.onboardingComplete, 
        authProvider: user.authProvider,
        message: 'Registration successful. Please complete your profile.',
        redirectTo: '/profile-setup'
    });
});

export const authUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email: email.toLowerCase().trim() });

    // 🔴 CHANGE 1: Handle User Not Found explicitly
    if (!user) {
        return res.status(404).json({ 
            message: 'Account does not exist. Please register.',
            error: 'USER_NOT_FOUND',
            redirectTo: '/register' 
        });
    }

    // 🔴 CHANGE 2: Handle Social Login users trying to use password
    if (!user.password) {
        return res.status(400).json({ 
            message: `This account uses ${user.authProvider} login. Please login with that.`,
            error: 'SOCIAL_LOGIN_REQUIRED',
            authProvider: user.authProvider 
        });
    }

    const isMatch = await user.matchPassword(password);
    
    if (isMatch) {
        setTokenCookie(res, user); 
        
        if (!user.profileComplete) {
            return res.json({ 
                uid: user.uid, 
                email: user.email, 
                name: user.name,
                userType: user.userType,
                profileComplete: user.profileComplete,
                onboardingComplete: user.onboardingComplete,
                authProvider: user.authProvider,
                message: 'Login successful. Please complete your profile.',
                redirectTo: '/profile-setup'
            });
        }
        
        if (user.userType === null) {
            return res.json({ 
                uid: user.uid, 
                email: user.email, 
                name: user.name,
                userType: user.userType,
                profileComplete: user.profileComplete,
                onboardingComplete: user.onboardingComplete,
                authProvider: user.authProvider,
                message: 'Login successful. Please select user type.',
                redirectTo: '/select-usertype'
            });
        }

        // ✅ UPDATED: Use Helper for Dynamic Path
        const dashboardPath = await getDashboardPath(user);
        
        res.json({ 
            uid: user.uid, 
            email: user.email, 
            name: user.name,
            phoneNumber: user.phoneNumber,
            dateOfBirth: user.dateOfBirth,
            gender: user.gender,
            userType: user.userType,
            profileComplete: user.profileComplete,
            onboardingComplete: user.onboardingComplete,
            authProvider: user.authProvider,
            message: 'Login successful',
            redirectTo: dashboardPath // Will be /dashboard or /dashboard/br_XXXX
        });
    } else {
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
            uid: req.user.uid, 
            email: req.user.email, 
            name: req.user.name,
            phoneNumber: req.user.phoneNumber,
            dateOfBirth: req.user.dateOfBirth,
            gender: req.user.gender,
            profilePicture: req.user.profilePicture,
            userType: req.user.userType,
            profileComplete: req.user.profileComplete, 
            onboardingComplete: req.user.onboardingComplete,
        },
    });
});

// =================================================================
// 3. PROFILE SETUP
// =================================================================

export const setupProfile = asyncHandler(async (req, res) => {
    if (!req.user) {
        return res.status(401).json({ 
            message: 'Not authorized, please login.', 
            redirectTo: '/login' 
        });
    }

    const { name, phoneNumber, dateOfBirth, gender } = req.body; 

    if (!name || !phoneNumber || !dateOfBirth || !gender) {
        res.status(400);
        throw new Error('All fields are required: name, phoneNumber, dateOfBirth, gender');
    }

    const validGenders = ['MALE', 'FEMALE', 'OTHER'];
    if (!validGenders.includes(gender)) {
        res.status(400);
        throw new Error('Invalid gender. Must be MALE, FEMALE, or OTHER.');
    }

    const phoneRegex = /^[+]?[\d\s\-()]+$/;
    if (!phoneRegex.test(phoneNumber)) {
        res.status(400);
        throw new Error('Invalid phone number format.');
    }

    const dob = new Date(dateOfBirth);
    if (isNaN(dob.getTime())) {
        res.status(400);
        throw new Error('Invalid date format for date of birth.');
    }

    const user = req.user;
    user.name = name.trim();
    user.phoneNumber = phoneNumber.trim();
    user.dateOfBirth = dob;
    user.gender = gender;
    user.profileComplete = true;

    await user.save();
    setTokenCookie(res, user);

    res.status(200).json({
        message: 'Profile setup completed successfully. Please select your user type.',
        user: {
             uid: user.uid, 
             email: user.email,
             name: user.name,
             phoneNumber: user.phoneNumber,
             dateOfBirth: user.dateOfBirth,
             gender: user.gender,
             profileComplete: user.profileComplete,
             userType: user.userType,
             onboardingComplete: user.onboardingComplete
        },
        redirectTo: '/select-usertype'
    });
});

// =================================================================
// 4. GOOGLE AUTH (Updated Redirects with UID)
// =================================================================

export const googleSignup = (req, res) => {
    const redirectUri = process.env.GOOGLE_REDIRECT_URI;
    const scopes = 'openid profile email'; 
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
            if (user) return res.redirect(`${FRONTEND_URL}/login?error=user_already_exists`);
            user = await User.create({ 
                email: email.toLowerCase().trim(), 
                name: name || email.split('@')[0],
                googleId, 
                userType: null, 
                profileComplete: false,
                onboardingComplete: false, 
                authProvider: 'GOOGLE',
                profilePicture: picture
            });
        } else {
            // 🔴 CHANGE 3: Redirect with data if user tries to Login but doesn't exist
            if (!user) {
                return res.redirect(`${FRONTEND_URL}/register?error=account_not_found&email=${encodeURIComponent(email)}&name=${encodeURIComponent(name)}`);
            }
            if (!user.googleId) {
                user.googleId = googleId;
                user.authProvider = 'GOOGLE';
                if (!user.name) user.name = name;
                if (!user.profilePicture) user.profilePicture = picture;
                await user.save();
            }
        }
        
        setTokenCookie(res, user);
        if (!user.profileComplete) return res.redirect(`${FRONTEND_URL}/profile-setup`); 
        if (user.userType === null) return res.redirect(`${FRONTEND_URL}/select-usertype`); 

        // ✅ UPDATED: Use Helper for Dynamic Path
        const dashboardPath = await getDashboardPath(user);
        
        return res.redirect(`${FRONTEND_URL}${dashboardPath}`);

    } catch (error) {
        console.error("Google Callback Error:", error);
        return res.redirect(`${FRONTEND_URL}/login?error=server_error`);
    }
});

// =================================================================
// 5. LINKEDIN AUTH (Updated Redirects with UID)
// =================================================================

export const linkedinSignup = (req, res) => {
    const redirectUri = encodeURIComponent(process.env.LINKEDIN_AUTH_REDIRECT_URI);
    const scope = encodeURIComponent('openid profile email');
    const state = `signup:${crypto.randomBytes(8).toString('hex')}`;
    const authUrl = `https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=${process.env.LINKEDIN_CLIENT_ID}&redirect_uri=${redirectUri}&state=${state}&scope=${scope}`;
    res.redirect(authUrl);
};

export const linkedinLogin = (req, res) => {
    const redirectUri = encodeURIComponent(process.env.LINKEDIN_AUTH_REDIRECT_URI);
    const scope = encodeURIComponent('openid profile email');
    const state = `login:${crypto.randomBytes(16).toString('hex')}`;
    const authUrl = `https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=${process.env.LINKEDIN_CLIENT_ID}&redirect_uri=${redirectUri}&state=${state}&scope=${scope}`;
    res.redirect(authUrl);
};

export const linkedinCallback = asyncHandler(async (req, res) => {
    const { code, state } = req.query;
    if (!code || !state) return res.redirect(`${FRONTEND_URL}/login?error=oauth_flow_error`);

    const stateParts = state.toString().split(':');
    const action = stateParts[0];
    const redirectUri = process.env.LINKEDIN_AUTH_REDIRECT_URI;
    let user;

    try {
        console.log('--- 🔗 LinkedIn Auth Flow Start ---');
        
        // 1. CODE TO ACCESS TOKEN EXCHANGE
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
        console.log('✅ 1. Access Token Received.');

        // 2. FETCH USER PROFILE (userinfo)
        const profileResponse = await axios.get('https://api.linkedin.com/v2/userinfo', {
            headers: { Authorization: `Bearer ${accessToken}` }
        });
        
        const { sub: linkedinId, email, name, picture } = profileResponse.data;
        const userEmail = email ? email.toLowerCase().trim() : null; 
        
        const findQuery = { $or: [{ linkedinId }] };
        if (userEmail) findQuery.$or.push({ email: userEmail });
        user = await User.findOne(findQuery);
        
        if (action === 'signup') {
            if (user) return res.redirect(`${FRONTEND_URL}/login?error=user_already_exists`);
            user = await User.create({ 
                email: userEmail, 
                name: name || 'LinkedIn User', 
                linkedinId, 
                userType: null, 
                profileComplete: false, 
                onboardingComplete: false, 
                authProvider: 'LINKEDIN',
                profilePicture: picture
            });
        } else {
             // 🔴 CHANGE 4: Redirect with data if user tries to Login but doesn't exist
            if (!user) {
                return res.redirect(`${FRONTEND_URL}/register?error=account_not_found&email=${encodeURIComponent(userEmail || '')}&name=${encodeURIComponent(name || '')}`);
            }
            if (!user.linkedinId) {
                user.linkedinId = linkedinId;
                user.authProvider = 'LINKEDIN';
                await user.save();
            }
        }
        
        setTokenCookie(res, user);
        if (!user.profileComplete) return res.redirect(`${FRONTEND_URL}/profile-setup`);
        if (user.userType === null) return res.redirect(`${FRONTEND_URL}/select-usertype`); 

        // ✅ UPDATED: Use Helper for Dynamic Path
        const dashboardPath = await getDashboardPath(user);
        
        return res.redirect(`${FRONTEND_URL}${dashboardPath}`);

    } catch (error) {
        console.error("LinkedIn Callback Error:", error.message);
        return res.redirect(`${FRONTEND_URL}/login?error=server_error`);
    }
});

// =================================================================
// 6. FACEBOOK/INSTAGRAM AUTH (Updated Redirects with UID)
// =================================================================

export const metaAuthStart = (req, res) => {
    const { platform } = req.params; 
    const redirectUri = process.env.META_AUTH_REDIRECT_URI; 
    let authProviderType, scopeFinal;
    
    if (platform === 'facebook') {
        authProviderType = 'FACEBOOK';
        scopeFinal = 'email,public_profile'; 
    } else if (platform === 'instagram') {
        authProviderType = 'INSTAGRAM';
        scopeFinal = 'email,public_profile'; 
    } else {
        res.status(400);
        throw new Error('Invalid platform for Meta Auth.');
    }

    const state = `${authProviderType}_auth:${crypto.randomBytes(8).toString('hex')}`;
    const authUrl = `${META_BASE_URL_OAUTH}?client_id=${process.env.META_APP_ID}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}&scope=${encodeURIComponent(scopeFinal)}`;
    res.redirect(authUrl);
};

export const metaAuthCallback = asyncHandler(async (req, res) => {
    const { code, state } = req.query;
    if (!code || !state) return res.redirect(`${FRONTEND_URL}/login?error=oauth_flow_error`);

    const stateParts = state.toString().split(':');
    const authProviderType = stateParts[0].split('_')[0]; 
    const redirectUri = process.env.META_AUTH_REDIRECT_URI;
    let user;

    try {
        const tokenData = await getMetaLongLivedToken(code, redirectUri);
        const { fbUserId, userEmail, userName, profilePicture } = tokenData;

        if (!fbUserId || !userEmail) return res.redirect(`${FRONTEND_URL}/login?error=meta_data_missing`);

        const findQuery = { $or: [{ facebookId: fbUserId }] };
        if (userEmail) findQuery.$or.push({ email: userEmail });
        user = await User.findOne(findQuery);
        
        if (!user) {
            user = await User.create({ 
                email: userEmail, 
                name: userName,
                facebookId: fbUserId, 
                profilePicture: profilePicture,
                userType: null, 
                profileComplete: false,
                onboardingComplete: false, 
                authProvider: authProviderType,
            });
        } else if (!user.facebookId) {
            user.facebookId = fbUserId;
            user.authProvider = authProviderType;
            await user.save();
        }

        setTokenCookie(res, user);
        if (!user.profileComplete) return res.redirect(`${FRONTEND_URL}/profile-setup`); 
        if (user.userType === null) return res.redirect(`${FRONTEND_URL}/select-usertype`); 

        // ✅ UPDATED: Use Helper for Dynamic Path
        const dashboardPath = await getDashboardPath(user);
        
        return res.redirect(`${FRONTEND_URL}${dashboardPath}`);

    } catch (error) {
        console.error("Meta Auth Callback Error:", error.message);
        return res.redirect(`${FRONTEND_URL}/login?error=server_error_meta`);
    }
});

// =================================================================
// 7. PASSWORD RESET
// =================================================================

export const sendResetCode = asyncHandler(async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) return res.json({ message: 'If a matching email was found, a reset code has been sent.' });
    
    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
    user.verificationCode = resetCode;
    user.codeExpiry = Date.now() + 10 * 60 * 1000;
    await user.save({ validateBeforeSave: false });

    await transporter.sendMail({
        to: user.email,
        subject: 'Password Reset Code for Dhanur',
        from: `"Dhanur App" <${process.env.EMAIL_USER}>`, 
        html: `Your password reset code is <strong>${resetCode}</strong>.`,
    });
    res.json({ message: 'Password reset code sent to your email.' });
});

export const resetPassword = asyncHandler(async (req, res) => {
    const { email, resetCode, newPassword } = req.body;
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user || user.verificationCode !== resetCode || user.codeExpiry < Date.now()) {
        res.status(400);
        throw new Error('Invalid or expired reset code.');
    }
    user.password = await bcrypt.hash(newPassword, 12);
    user.verificationCode = undefined;
    user.codeExpiry = undefined;
    await user.save();
    await invalidateSession(user._id);
    res.status(200).json({ message: 'Password has been reset successfully. Please login.' });
});

// =================================================================
// 8. USERTYPE SELECTION (After Profile Setup)
// =================================================================

export const selectUserType = asyncHandler(async (req, res) => {
    if (!req.user) {
        return res.status(401).json({ message: 'Not authorized, please login.', redirectTo: '/login' });
    }

    const { userType } = req.body;
    const validTypes = ['BRAND', 'INFLUENCER'];
    
    if (!userType || !validTypes.includes(userType)) {
        res.status(400); 
        throw new Error('Invalid user type. Must be BRAND or INFLUENCER.');
    }

    const user = req.user;
    if (!user.profileComplete) {
        return res.status(400).json({ message: 'Please complete your profile first.', redirectTo: '/profile-setup' });
    }

    if (user.userType && user.userType !== userType) {
        res.status(400);
        throw new Error(`Conflict: You are already registered as ${user.userType}.`);
    }

    if (!user.userType) {
        user.userType = userType;
        user.onboardingComplete = userType === 'BRAND' ? false : true;
        await user.save();
        setTokenCookie(res, user); 
    }
    
    // ✅ Logic Updated:
    // Brand -> /onboarding (to create brand)
    // Influencer -> /dashboard
    let dashboardPath = user.userType === 'BRAND' ? '/onboarding' : '/dashboard';
    
    res.status(200).json({
        message: `User type set to ${user.userType}.`,
        user: { 
            uid: user.uid, 
            email: user.email,
            name: user.name,
            phoneNumber: user.phoneNumber, 
            dateOfBirth: user.dateOfBirth,
            gender: user.gender,
            userType: user.userType, 
            profileComplete: user.profileComplete,
            onboardingComplete: user.onboardingComplete
        },
        redirectTo: dashboardPath
    });
});