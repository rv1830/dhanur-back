import asyncHandler from 'express-async-handler';
import Brand from '../models/Brand.js';
import User from '../models/User.js';
import crypto from 'crypto';

// =================================================================
// 1. CREATE BRAND
// =================================================================
export const createBrand = asyncHandler(async (req, res) => {
    const { brandName, industry, companyEmail, website, description } = req.body;
    const user = req.user;

    console.log(`🚀 Creating brand for User: ${user.uid}`);

    if (user.userType === 'INFLUENCER') {
        res.status(403);
        throw new Error('Influencers cannot create brands.');
    }

    // INDUSTRY FIX: members array mein Mongo _id hi rahega internal linking ke liye
    const brand = await Brand.create({
        brandName,
        industry,
        companyEmail,
        website,
        description,
        members: [{ user: user._id, role: 'BRAND ADMIN' }]
    });

    // User status update
    user.userType = 'BRAND';
    user.onboardingComplete = true;
    await user.save();

    console.log(`✅ Brand Created: ${brand.brandName} (ID: ${brand.bid})`);

    // ✅ FIXED: Redirect to 'bid' (BR-12345678) instead of Mongo _id
    res.status(201).json({ 
        success: true, 
        brand: {
            bid: brand.bid,
            brandName: brand.brandName,
            industry: brand.industry
        }, 
        redirectTo: `/dashboard/brand/${brand.bid}` 
    });
});

// =================================================================
// 2. INVITE MEMBER
// =================================================================
export const inviteToBrand = asyncHandler(async (req, res) => {
    const { email, role, bid } = req.body; // bid: BR-12345678 bhejenge frontend se

    // FIXED: Find brand by bid
    const brand = await Brand.findOne({ bid });

    if (!brand) { 
        res.status(404); 
        throw new Error('Brand not found'); 
    }

    // Check if user is already a member
    const invitationToken = crypto.randomBytes(32).toString('hex');

    brand.invitations.push({
        email: email.toLowerCase().trim(),
        role,
        token: invitationToken,
        invitedBy: req.user._id
    });

    await brand.save();

    const inviteLink = `${process.env.FRONTEND_URL}/join-brand?token=${invitationToken}`;

    console.log(`📧 Invite generated for ${email} in Brand: ${brand.brandName}`);

    res.json({ 
        success: true, 
        message: `Invite generated for ${email}`,
        inviteLink 
    });
});

// =================================================================
// 3. GET INVITE DETAILS
// =================================================================
export const getInviteDetails = asyncHandler(async (req, res) => {
    const { token } = req.params;
    
    // Brand find by token in invitations array
    const brand = await Brand.findOne({ "invitations.token": token });

    if (!brand) {
        res.status(404);
        throw new Error('Invitation link is invalid or expired.');
    }

    const invite = brand.invitations.find(inv => inv.token === token);
    
    res.json({
        brandName: brand.brandName,
        role: invite.role,
        email: invite.email,
        bid: brand.bid // Return bid for frontend consistency
    });
});

// =================================================================
// 4. JOIN BRAND
// =================================================================
export const joinBrand = asyncHandler(async (req, res) => {
    const { token } = req.body;
    const user = req.user; // Logged-in user from protect middleware

    const brand = await Brand.findOne({ "invitations.token": token });
    if (!brand) {
        res.status(400);
        throw new Error('Invalid or expired invitation.');
    }

    const invite = brand.invitations.find(inv => inv.token === token);

    // SECURITY: Email match
    if (invite.email !== user.email) {
        res.status(403);
        throw new Error('This invite was sent to a different email address.');
    }

    // 1. Add member to brand
    brand.members.push({ user: user._id, role: invite.role });
    
    // 2. Remove invite
    brand.invitations = brand.invitations.filter(i => i.token !== token);
    await brand.save();

    // 3. Update User status
    // Industry fix: If it's a member being invited, userType should be 'MEMBER'
    user.userType = 'MEMBER'; 
    user.onboardingComplete = true;
    await user.save();

    console.log(`🤝 User ${user.uid} joined Brand ${brand.brandName} as ${invite.role}`);

    res.json({ 
        success: true, 
        message: `Welcome to ${brand.brandName}!`,
        redirectTo: `/dashboard/brand/${brand.bid}`
    });
});