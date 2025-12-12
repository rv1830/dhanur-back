import asyncHandler from 'express-async-handler';
import bcrypt from 'bcryptjs'; // ✅ ADDED FOR MANUAL HASHING
import User from '../models/User.js';
import { setTokenCookie, invalidateSession } from '../utils/authUtils.js'; 
import { cookieOptions } from '../middleware/authMiddleware.js'; 
import { OAuth2Client } from 'google-auth-library';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import twilio from 'twilio';
import axios from 'axios';

// =================================================================
// ⚙️ EXTERNAL SERVICE SETUP (UNCHANGED)
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
    
    // ✅ MANUAL HASHING - 100% RELIABLE
    const hashedPassword = await bcrypt.hash(password, 12);
    const user = await User.create({ 
        email: email.toLowerCase().trim(), 
        password: hashedPassword, 
        userType, 
        authProvider: 'LOCAL' 
    });
    
    setTokenCookie(res, user); 
    res.status(201).json({ _id: user._id, email: user.email, userType: user.userType });
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
        res.json({ _id: user._id, email: user.email, userType: user.userType });
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
    
    // ✅ MANUAL HASHING
    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();
    await invalidateSession(user._id);
    res.clearCookie('token', cookieOptions);
    res.status(200).json({ message: 'Password changed successfully. Please log in again.' });
});

export const checkAuthStatus = asyncHandler(async (req, res) => {
    res.status(200).json({
        isAuthenticated: true,
        user: { _id: req.user._id, email: req.user.email, userType: req.user.userType },
    });
});

// =================================================================
// 3. SOCIAL AUTH (Google & LinkedIn) - UNCHANGED
// =================================================================

export const googleLogin = (req, res) => {
    const redirectUri = process.env.GOOGLE_REDIRECT_URI; 
    const scopes = 'openid profile email'; 
    const state = crypto.randomBytes(16).toString('hex');

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
        res.status(400); 
        throw new Error('OAuth flow error: Missing code or state.');
    }

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

    const profileResponse = await axios.get('https://www.googleapis.com/oauth2/v3/userinfo', {
        headers: { Authorization: `Bearer ${access_token}` }
    });
    
    const { sub: googleId, email, given_name } = profileResponse.data;
    const assumedUserType = 'BRAND'; 

    let user = await User.findOne({ $or: [{ googleId }, { email }] });
    
    if (!user) {
        user = await User.create({ email, googleId, userType: assumedUserType, authProvider: 'GOOGLE' });
    } else if (!user.googleId) {
        user.googleId = googleId;
        user.authProvider = 'GOOGLE';
        await user.save();
    }
    
    setTokenCookie(res, user);
    res.redirect(`${process.env.FRONTEND_URL}/?token_set=true`); 
});

export const linkedinLogin = (req, res) => {
    const scope = encodeURIComponent('r_liteprofile r_emailaddress');
    const redirectUri = encodeURIComponent(process.env.LINKEDIN_REDIRECT_URI);
    const state = crypto.randomBytes(16).toString('hex');

    const authUrl = `https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=${process.env.LINKEDIN_CLIENT_ID}&redirect_uri=${redirectUri}&state=${state}&scope=${scope}`;
    res.redirect(authUrl);
};

export const linkedinCallback = asyncHandler(async (req, res) => {
    const { code, state } = req.query;

    if (!code || !state) {
        res.status(400); 
        throw new Error('OAuth flow error: Missing code or state.');
    }

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

    const profileResponse = await axios.get('https://api.linkedin.com/v2/userinfo', {
        headers: { Authorization: `Bearer ${accessToken}` }
    });
    
    const { sub: linkedinId, email } = profileResponse.data;
    const assumedUserType = 'BRAND'; 

    let user = await User.findOne({ $or: [{ linkedinId }, { email }] });
    
    if (!user) {
        user = await User.create({ email, linkedinId, userType: assumedUserType, authProvider: 'LINKEDIN' });
    } else if (!user.linkedinId) {
        user.linkedinId = linkedinId;
        user.authProvider = 'LINKEDIN';
        await user.save();
    }
    
    setTokenCookie(res, user);
    res.redirect(`${process.env.FRONTEND_URL}/?token_set=true`); 
});

// =================================================================
// 4. OTP LOGIN (Phone Number) - UNCHANGED
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
            userType: 'BRAND', 
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
        message: 'Login successful via OTP.' 
    });
});

// =================================================================
// 5. PASSWORD RESET (Email)
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

    // ✅ MANUAL HASHING - NO PRE-SAVE DEPENDENCY
    user.password = await bcrypt.hash(newPassword, 12);
    user.verificationCode = undefined;
    user.codeExpiry = undefined;
    await user.save();
    
    await invalidateSession(user._id);
    
    res.status(200).json({ message: 'Password has been reset successfully. Please login.' });
});