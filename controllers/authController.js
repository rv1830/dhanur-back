// --- controllers/authController.js (UPDATED with Meta Auth) ---

import asyncHandler from 'express-async-handler';
import bcrypt from 'bcryptjs';
import User from '../models/User.js';
import { setTokenCookie, invalidateSession } from '../utils/authUtils.js'; 
import { cookieOptions } from '../middleware/authMiddleware.js'; 
import { OAuth2Client } from 'google-auth-library';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import axios from 'axios';
import { getMetaLongLivedToken } from '../services/metaService.js'; // Import token service

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
        // --- HARDCODED CREDENTIALS START ---
        user: 'outreach@linkup.capital', 
        pass: 'dwxi ieuy yhmq lixf', 
        // --- HARDCODED CREDENTIALS END ---
    },
});

transporter.verify((error, success) => {
    if (error) {
        console.error("❌ SMTP Transporter Verification Failed:", error.message);
        console.error("   -> Check the hardcoded App Password.");
    } else {
        console.log("✅ SMTP Transporter Ready. (Using Hardcoded Auth)");
    }
});

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

// =================================================================
// 1. BASIC EMAIL/PASSWORD AUTH
// =================================================================

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
        userType: null,
        profileComplete: false, 
        onboardingComplete: false,
        authProvider: 'LOCAL' 
    });
    
    setTokenCookie(res, user); 
    res.status(201).json({ 
        _id: user._id, 
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
    if (!user || !user.password) {
        res.status(401); 
        throw new Error('Invalid email or password');
    }
    
    const isMatch = await user.matchPassword(password);
    
    if (isMatch) {
        setTokenCookie(res, user); 
        
        if (!user.profileComplete) {
            return res.json({ 
                _id: user._id, 
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
                _id: user._id, 
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

        const dashboardPath = user.userType === 'BRAND' ? '/dashboard/brand' : 
                             user.userType === 'INFLUENCER' ? '/dashboard/influencer' : '/dashboard';
        
        res.json({ 
            _id: user._id, 
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
            redirectTo: dashboardPath
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
            _id: req.user._id, 
            email: req.user.email, 
            name: req.user.name,
            phoneNumber: req.user.phoneNumber,
            dateOfBirth: req.user.dateOfBirth,
            gender: req.user.gender,
            profilePicture: req.user.profilePicture,
            userType: req.user.userType,
            profileComplete: req.user.profileComplete, 
            onboardingComplete: req.user.onboardingComplete,
            authProvider: req.user.authProvider,
            googleId: req.user.googleId || null,
            linkedinId: req.user.linkedinId || null,
            facebookId: req.user.facebookId || null, // NEW
        },
    });
});

// =================================================================
// 3. PROFILE SETUP (phoneNumber is mandatory here)
// =================================================================

export const setupProfile = asyncHandler(async (req, res) => {
    const userId = req.user._id;
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

    // ✅ Phone number validation
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
             _id: user._id,
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
// 4. GOOGLE AUTH (NO CHANGE)
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
            if (user) {
                return res.redirect(`${FRONTEND_URL}/login?error=user_already_exists`);
            }

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
            if (!user) {
                return res.redirect(`${FRONTEND_URL}/register?error=no_account_found`);
            }

            if (!user.googleId) {
                user.googleId = googleId;
                user.authProvider = 'GOOGLE';
                if (!user.name) user.name = name;
                if (!user.profilePicture) user.profilePicture = picture;
                await user.save();
            }
        }
        
        // 🚨 REDIRECT LOGIC
        setTokenCookie(res, user);
        
        if (!user.profileComplete) {
            return res.redirect(`${FRONTEND_URL}/profile-setup`); 
        }
        
        if (user.userType === null) {
            return res.redirect(`${FRONTEND_URL}/select-usertype`); 
        }

        let dashboardPath = user.userType === 'BRAND' ? '/dashboard/brand' : 
                                 user.userType === 'INFLUENCER' ? '/dashboard/influencer' : '/dashboard';
        
        return res.redirect(`${FRONTEND_URL}${dashboardPath}`);

    } catch (error) {
        console.error("Google Callback Error:", error);
        return res.redirect(`${FRONTEND_URL}/login?error=server_error`);
    }
});

// =================================================================
// 5. LINKEDIN AUTH 
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

    if (!code || !state) {
        return res.redirect(`${FRONTEND_URL}/login?error=oauth_flow_error`);
    }

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
        
        console.log('✅ 2. Profile Data Fetched:', { linkedinId, email: userEmail, name }); 
        
        // 3. USER FIND/CREATE LOGIC
        const findQuery = { $or: [{ linkedinId }] };
        if (userEmail) {
            findQuery.$or.push({ email: userEmail });
        }
        
        user = await User.findOne(findQuery);
        
        if (action === 'signup') {
            if (user) {
                return res.redirect(`${FRONTEND_URL}/login?error=user_already_exists`);
            }

            // Create User: Uses userEmail (which might be null)
            const newUser = await User.create({ 
                email: userEmail, 
                name: name || 'LinkedIn User', 
                linkedinId, 
                userType: null, 
                profileComplete: false, 
                onboardingComplete: false, 
                authProvider: 'LINKEDIN',
                profilePicture: picture
            });
            
            if (!newUser) {
                throw new Error("Failed to create user entry in database during signup.");
            }
            
            user = newUser; 
            console.log('✅ 3. New User CREATED successfully:', user._id);
            
        } else { // Login
            if (!user) {
                return res.redirect(`${FRONTEND_URL}/register?error=no_account_found`);
            }

            // Link existing user if logging in with email match
            if (!user.linkedinId) {
                user.linkedinId = linkedinId;
                user.authProvider = 'LINKEDIN';
                if (!user.name) user.name = name;
                if (!user.profilePicture) user.profilePicture = picture;
                await user.save();
            }
            console.log('✅ 3. User LOGGED IN/LINKED successfully.');
        }
        
        // 4. SET TOKEN AND REDIRECT
        setTokenCookie(res, user);
        console.log('✅ 4. JWT Token Set in Cookie.');
        
        if (!user.profileComplete) {
            return res.redirect(`${FRONTEND_URL}/profile-setup`);
        }
        
        if (user.userType === null) {
            return res.redirect(`${FRONTEND_URL}/select-usertype`); 
        }

        let dashboardPath = user.userType === 'BRAND' ? '/dashboard/brand' : 
                                 user.userType === 'INFLUENCER' ? '/dashboard/influencer' : '/dashboard';
        
        return res.redirect(`${FRONTEND_URL}${dashboardPath}`);

    } catch (error) {
        console.error("❌ FATAL LinkedIn Callback Error:", error.response?.data || error.message);
        
        let errorMessage = "LinkedIn login failed. Please check credentials or permissions.";
        if (error.response && error.response.status === 403) {
             errorMessage = 'Permission denied. Check your LinkedIn App scopes (OpenID, Profile, Email).';
        }

        return res.redirect(`${FRONTEND_URL}/login?error=${encodeURIComponent(errorMessage)}`);
    }
});


// =================================================================
// 6. FACEBOOK/INSTAGRAM AUTH (NEW BLOCK)
// =================================================================

// --- controllers/authController.js (FIXED metaAuthStart) ---

// Note: Assuming necessary imports like asyncHandler, User, setTokenCookie, etc., are present.
// Note: Assuming META_BASE_URL_OAUTH and FRONTEND_URL are defined in the file scope.

export const metaAuthStart = (req, res) => {
    const { platform } = req.params; // 'facebook' or 'instagram'
    const redirectUri = process.env.META_AUTH_REDIRECT_URI; 
    
    let authProviderType;
    let scopeFinal;
    
    if (platform === 'facebook') {
        authProviderType = 'FACEBOOK';
        // ✅ Facebook Auth: Only basic permissions needed.
        scopeFinal = 'email,public_profile'; 
    } else if (platform === 'instagram') {
        authProviderType = 'INSTAGRAM';
        // 🚨 FIX: Instagram Auth should only request basic permissions (email, public_profile).
        // The extensive scopes (pages_show_list, instagram_basic, etc.) are only required
        // during the separate Social Connect flow to fetch analytics/page details.
        scopeFinal = 'email,public_profile'; // FIXED to minimal scope for Auth
    } else {
        res.status(400);
        throw new Error('Invalid platform for Meta Auth.');
    }

    const state = `${authProviderType}_auth:${crypto.randomBytes(8).toString('hex')}`;

    const authUrl = `${META_BASE_URL_OAUTH}?` +
        `client_id=${process.env.META_APP_ID}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&state=${state}` +
        `&scope=${encodeURIComponent(scopeFinal)}`;
        
    res.redirect(authUrl);
};

export const metaAuthCallback = asyncHandler(async (req, res) => {
    const { code, state } = req.query;

    if (!code || !state) {
        return res.redirect(`${FRONTEND_URL}/login?error=oauth_flow_error`);
    }

    const stateParts = state.toString().split(':');
    const authProviderType = stateParts[0].split('_')[0]; // 'FACEBOOK' or 'INSTAGRAM'

    const redirectUri = process.env.META_AUTH_REDIRECT_URI;
    let user;

    try {
        // 1. Get User/Long Lived Token Info
        // Note: getMetaLongLivedToken internally fetches the user's basic profile (ID, email, name)
        const tokenData = await getMetaLongLivedToken(code, redirectUri);
        const { longLivedToken, fbUserId, userEmail, userName, profilePicture } = tokenData;

        if (!fbUserId || !userEmail) {
            return res.redirect(`${FRONTEND_URL}/login?error=meta_data_missing`);
        }

        // 2. Find/Create User Logic: Find by Facebook ID or Email
        const findQuery = { $or: [{ facebookId: fbUserId }] };
        if (userEmail) {
            findQuery.$or.push({ email: userEmail });
        }
        user = await User.findOne(findQuery);
        
        if (!user) {
            // New User Registration
            user = await User.create({ 
                email: userEmail, 
                name: userName,
                facebookId: fbUserId, 
                profilePicture: profilePicture,
                userType: null, 
                profileComplete: false,
                onboardingComplete: false, 
                authProvider: authProviderType, // FACEBOOK or INSTAGRAM
            });
        } else {
            // Existing user: Link FB ID if missing and update provider if changing from LOCAL
            if (!user.facebookId) {
                user.facebookId = fbUserId;
                user.authProvider = authProviderType;
                if (!user.name) user.name = userName;
                if (!user.profilePicture) user.profilePicture = profilePicture;
                await user.save();
            }
        }

        // 3. REDIRECT LOGIC
        setTokenCookie(res, user);
        
        if (!user.profileComplete) {
            return res.redirect(`${FRONTEND_URL}/profile-setup`); 
        }
        if (user.userType === null) {
            return res.redirect(`${FRONTEND_URL}/select-usertype`); 
        }

        let dashboardPath = user.userType === 'BRAND' ? '/dashboard/brand' : 
                                 user.userType === 'INFLUENCER' ? '/dashboard/influencer' : '/dashboard';
        
        return res.redirect(`${FRONTEND_URL}${dashboardPath}`);

    } catch (error) {
        console.error("Meta Auth Callback Error:", error.response?.data || error.message);
        return res.redirect(`${FRONTEND_URL}/login?error=server_error_meta`);
    }
});

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
            from: `"Dhanur App" <${process.env.EMAIL_USER}>`, 
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
// 8. USERTYPE SELECTION (After Profile Setup)
// =================================================================

export const selectUserType = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    const { userType } = req.body;

    const validTypes = ['BRAND', 'INFLUENCER'];
    if (!userType || !validTypes.includes(userType)) {
        res.status(400); 
        throw new Error('Invalid user type. Must be BRAND or INFLUENCER.');
    }

    const user = req.user;

    // 🛡️ Profile complete check
    if (!user.profileComplete) {
        res.status(400);
        throw new Error('Please complete your profile first before selecting user type.');
    }

    // 🛡️ Conflict check
    if (user.userType && user.userType !== userType) {
        res.status(400);
        throw new Error(`Conflict: You are already registered as ${user.userType}. Cannot change to both.`);
    }

    // Update user
    if (!user.userType) {
        user.userType = userType;
        user.onboardingComplete = true;
        await user.save();
        
        setTokenCookie(res, user); 
    } else if (user.userType === userType && !user.onboardingComplete) {
        user.onboardingComplete = true;
        await user.save();
        setTokenCookie(res, user); 
    }
    
    let dashboardPath = user.userType === 'BRAND' ? '/dashboard/brand' : '/dashboard/influencer';
    
    res.status(200).json({
        message: `User type set to ${user.userType}. Onboarding complete.`,
        user: { 
            _id: user._id, 
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