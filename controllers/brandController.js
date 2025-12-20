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

    // 1. Influencer Check
    if (user.userType === 'INFLUENCER') {
        res.status(403);
        throw new Error('Influencers cannot create brands.');
    }

    // 2. DUPLICATE CHECK
    const brandExists = await Brand.findOne({
        $or: [
            { brandName: { $regex: new RegExp(`^${brandName.trim()}$`, 'i') } }, 
            { companyEmail: companyEmail.toLowerCase().trim() }
        ]
    });

    if (brandExists) {
        res.status(400);
        const message = brandExists.brandName.toLowerCase() === brandName.trim().toLowerCase() 
            ? 'A brand with this name already exists.' 
            : 'A brand with this company email already exists.';
        throw new Error(message);
    }

    // 3. Create Brand
    const brand = await Brand.create({
        brandName: brandName.trim(),
        industry,
        companyEmail: companyEmail.toLowerCase().trim(),
        website,
        description,
        members: [{ user: user._id, role: 'BRAND ADMIN' }]
    });

    // 4. User status update
    if (user.userType !== 'BRAND') {
        user.userType = 'BRAND';
    }
    user.onboardingComplete = true;
    await user.save();

    console.log(`✅ Brand Created: ${brand.brandName} by ${user.uid}`);

    res.status(201).json({ 
        success: true, 
        brand: { bid: brand.bid, brandName: brand.brandName }, 
        // ✅ CORRECTED PATH: /dashboard/br_XXXX (Removed /brand)
        redirectTo: `/dashboard/${brand.bid}` 
    });
});

// =================================================================
// 2. GET ALL MY BRANDS
// =================================================================
export const getMyBrands = asyncHandler(async (req, res) => {
    const brands = await Brand.find({ "members.user": req.user._id })
        .select('bid brandName members') 
        .populate('members.user', 'name'); 
    const formattedBrands = brands.map(brand => {
        const currentUserMember = brand.members.find(
            m => m.user._id.toString() === req.user._id.toString()
        );

        return {
            bid: brand.bid,
            brandName: brand.brandName,
            myRole: currentUserMember ? currentUserMember.role : null,
            myName: req.user.name 
        };
    });

    res.json({ 
        success: true, 
        count: formattedBrands.length,
        brands: formattedBrands 
    });
});

// =================================================================
// 3. GET BRAND DETAILS BY ID
// =================================================================
export const getBrandDetails = asyncHandler(async (req, res) => {
    const { bid } = req.params;

    const brand = await Brand.findOne({ bid })
        .populate('members.user', 'name email profileImage');

    if (!brand) {
        res.status(404);
        throw new Error('Brand not found');
    }

    // Security: Check if requesting user belongs to this brand
    const isMember = brand.members.some(m => m.user._id.toString() === req.user._id.toString());
    if (!isMember) {
        res.status(403);
        throw new Error('Access denied to this brand.');
    }

    res.json({ success: true, brand });
});

// =================================================================
// 4. INVITE MEMBER
// =================================================================
export const inviteToBrand = asyncHandler(async (req, res) => {
    const { email, role, bid } = req.body;
    const brand = await Brand.findOne({ bid });

    if (!brand) { res.status(404); throw new Error('Brand not found'); }

    const invitationToken = crypto.randomBytes(32).toString('hex');
    brand.invitations.push({
        email: email.toLowerCase().trim(),
        role,
        token: invitationToken,
        invitedBy: req.user._id
    });

    await brand.save();
    const inviteLink = `${process.env.FRONTEND_URL}/join-brand?token=${invitationToken}`;

    res.json({ success: true, message: `Invite generated for ${email}`, inviteLink });
});

// =================================================================
// 5. GET INVITE DETAILS
// =================================================================
export const getInviteDetails = asyncHandler(async (req, res) => {
    const { token } = req.params;
    const brand = await Brand.findOne({ "invitations.token": token });

    if (!brand) { res.status(404); throw new Error('Invalid or expired token.'); }

    const invite = brand.invitations.find(inv => inv.token === token);
    res.json({ brandName: brand.brandName, role: invite.role, email: invite.email, bid: brand.bid });
});

// =================================================================
// 6. JOIN BRAND (Multi-Role Logic)
// =================================================================
export const joinBrand = asyncHandler(async (req, res) => {
    const { token } = req.body;
    const user = req.user;

    if (user.userType === 'INFLUENCER') {
        res.status(403);
        throw new Error('Influencers cannot join brands.');
    }

    const brand = await Brand.findOne({ "invitations.token": token });
    if (!brand) { res.status(400); throw new Error('Invalid invitation.'); }

    const invite = brand.invitations.find(inv => inv.token === token);
    
    // Email check
    if (invite.email !== user.email) {
        res.status(403);
        throw new Error('Email mismatch.');
    }

    // Add to member list
    brand.members.push({ user: user._id, role: invite.role });
    brand.invitations = brand.invitations.filter(i => i.token !== token);
    await brand.save();

    user.onboardingComplete = true; 
    await user.save();

    res.json({ 
        success: true, 
        message: `You have been added to ${brand.brandName}.`, 
        // ✅ CORRECTED PATH: /dashboard/br_XXXX (Removed /brand)
        redirectTo: user.userType === null ? '/select-usertype' : `/dashboard/${brand.bid}`
    });
});