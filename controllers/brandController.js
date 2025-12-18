import asyncHandler from 'express-async-handler';
import Brand from '../models/Brand.js';
import User from '../models/User.js';
import crypto from 'crypto';

// 1. CREATE BRAND: Jab main banda brand banata hai
export const createBrand = asyncHandler(async (req, res) => {
    const { brandName, industry, companyEmail, website, description } = req.body;
    const user = req.user;

    if (user.userType === 'INFLUENCER') {
        res.status(403);
        throw new Error('Influencers cannot create brands.');
    }

    const brand = await Brand.create({
        brandName,
        industry,
        companyEmail,
        website,
        description,
        members: [{ user: user._id, role: 'BRAND ADMIN' }]
    });

    user.userType = 'BRAND';
    user.onboardingComplete = true;
    await user.save();

    // ✅ Yahan BRAND ID ke saath redirect path bhejein
    res.status(201).json({ 
        success: true, 
        brand, 
        redirectTo: `/dashboard/brand/${brand._id}` // <--- Brand ID yahan bhej di
    });
});

// 2. INVITE MEMBER: Admin/Manager link generate karke bhejenge
export const inviteToBrand = asyncHandler(async (req, res) => {
    const { email, role, brandId } = req.body;
    const brand = await Brand.findById(brandId);

    if (!brand) { res.status(404); throw new Error('Brand not found'); }

    // Generate Unique Token
    const invitationToken = crypto.randomBytes(32).toString('hex');

    brand.invitations.push({
        email: email.toLowerCase(),
        role,
        token: invitationToken,
        invitedBy: req.user._id
    });

    await brand.save();

    // Frontend URL for the user to click
    const inviteLink = `${process.env.FRONTEND_URL}/join-brand?token=${invitationToken}`;

    res.json({ 
        success: true, 
        message: `Invite generated for ${email}`,
        inviteLink // Ye link aap email mein bhejoge
    });
});

// 3. GET INVITE DETAILS: Naya banda link pe click karega toh brand info dikhegi
export const getInviteDetails = asyncHandler(async (req, res) => {
    const { token } = req.params;
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
        brandId: brand._id
    });
});

// 4. JOIN BRAND: Final step jab banda register karke button dabayega
export const joinBrand = asyncHandler(async (req, res) => {
    const { token } = req.body;
    const user = req.user; // Ye logged-in user hai

    const brand = await Brand.findOne({ "invitations.token": token });
    if (!brand) {
        res.status(400);
        throw new Error('Invalid or expired invitation.');
    }

    const invite = brand.invitations.find(inv => inv.token === token);

    // SECURITY: Email match honi chahiye
    if (invite.email !== user.email) {
        res.status(403);
        throw new Error('This invite was sent to a different email address.');
    }

    // Add member & Clean up invite
    brand.members.push({ user: user._id, role: invite.role });
    brand.invitations = brand.invitations.filter(i => i.token !== token);
    await brand.save();

    // Update User to Brand Member
    user.userType = 'BRAND';
    user.onboardingComplete = true;
    await user.save();

    res.json({ success: true, message: `Welcome to ${brand.brandName}!` });
});