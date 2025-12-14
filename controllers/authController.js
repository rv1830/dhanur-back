// --- controllers/authController.js (FINAL & COMPLETE) ---

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
        },
    });
});

// =================================================================
// 3. PROFILE SETUP (NEW STEP)
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
// 4. GOOGLE AUTH
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

// 🔥 googleCallback (Fixed Redirect)
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
        
        // 🚨 REDIRECT LOGIC
        setTokenCookie(res, user);
        
        // 1. Profile incomplete → /profile-setup
        if (!user.profileComplete) {
            return res.redirect(`${FRONTEND_URL}/profile-setup`); 
        }
        
        // 2. UserType null → /select-usertype
        if (user.userType === null) {
            return res.redirect(`${FRONTEND_URL}/select-usertype`); 
        }

        // 3. Else → Dashboard
        let dashboardPath = user.userType === 'BRAND' ? '/dashboard/brand' : 
                             user.userType === 'INFLUENCER' ? '/dashboard/influencer' : '/dashboard';
        
        return res.redirect(`${FRONTEND_URL}${dashboardPath}`);

    } catch (error) {
        console.error("Google Callback Error:", error);
        return res.redirect(`${FRONTEND_URL}/login?error=server_error`);
    }
});

// =================================================================
// 5. LINKEDIN AUTH (CRITICAL FIX APPLIED)
// =================================================================

export const linkedinSignup = (req, res) => {
    // 🔑 FIX: Auth flow के लिए नया वेरिएबल उपयोग करें
    const redirectUri = encodeURIComponent(process.env.LINKEDIN_AUTH_REDIRECT_URI);
    const scope = encodeURIComponent('openid profile email');
    const state = `signup:${crypto.randomBytes(8).toString('hex')}`;

    const authUrl = `https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=${process.env.LINKEDIN_CLIENT_ID}&redirect_uri=${redirectUri}&state=${state}&scope=${scope}`;
    res.redirect(authUrl);
};

export const linkedinLogin = (req, res) => {
    // 🔑 FIX: Auth flow के लिए नया वेरिएबल उपयोग करें
    const redirectUri = encodeURIComponent(process.env.LINKEDIN_AUTH_REDIRECT_URI);
    const scope = encodeURIComponent('openid profile email');
    const state = `login:${crypto.randomBytes(16).toString('hex')}`;

    const authUrl = `https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=${process.env.LINKEDIN_CLIENT_ID}&redirect_uri=${redirectUri}&state=${state}&scope=${scope}`;
    res.redirect(authUrl);
};

// 🔥 linkedinCallback (FIXED for missing email/DB entry failure + Added Debugging)
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
        
        // 🔑 CRITICAL FIX: Handle missing email (set to null if not provided by LinkedIn)
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
            
            // Check if DB operation failed silently (unlikely but safe check)
            if (!newUser) {
                throw new Error("Failed to create user entry in database during signup.");
            }
            
            user = newUser; 
            console.log('✅ 3. New User CREATED successfully:', user._id);
            
        } else { // Login
            if (!user) {
                return res.redirect(`${FRONTEND_URL}/signup?error=no_account_found`);
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
        // Log the exact error and redirect to login with error message
        console.error("❌ FATAL LinkedIn Callback Error:", error.response?.data || error.message);
        
        let errorMessage = "LinkedIn login failed. Please check credentials or permissions.";
        if (error.response && error.response.status === 403) {
             errorMessage = 'Permission denied. Check your LinkedIn App scopes (OpenID, Profile, Email).';
        }

        return res.redirect(`${FRONTEND_URL}/login?error=${encodeURIComponent(errorMessage)}`);
    }
});

// =================================================================
// 6-8. OTP, PASSWORD RESET, USERTYPE (No changes needed)
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
            userType: null,
            profileComplete: false, // 👈 OTP se bhi profile incomplete
            onboardingComplete: false,
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

// 🔥 UPDATED: verifyOtp with proper redirects
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
    
    // 🚨 REDIRECT LOGIC
    let redirectTo = null;
    
    if (!user.profileComplete) {
        redirectTo = '/profile-setup';
    } else if (user.userType === null) {
        redirectTo = '/select-usertype';
    } else {
        redirectTo = user.userType === 'BRAND' ? '/dashboard/brand' : 
                     user.userType === 'INFLUENCER' ? '/dashboard/influencer' : '/dashboard';
    }
    
    res.status(200).json({ 
        _id: user._id, 
        phoneNumber: user.phoneNumber,
        name: user.name,
        userType: user.userType,
        profileComplete: user.profileComplete,
        onboardingComplete: user.onboardingComplete,
        authProvider: user.authProvider,
        message: 'Login successful via OTP.',
        redirectTo: redirectTo
    });
});

// =================================================================
// 7. PASSWORD RESET (Email)
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