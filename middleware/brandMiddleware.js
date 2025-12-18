import asyncHandler from 'express-async-handler';
import Brand from '../models/Brand.js';

export const checkBrandRole = (allowedRoles) => {
    return asyncHandler(async (req, res, next) => {
        // EXACT FIX: Search for 'bid' from all possible sources
        const bid = req.params.bid || req.body.bid || req.params.brandId; 
        const userId = req.user._id; 

        if (!bid) {
            res.status(400);
            throw new Error('Brand ID (bid) is missing.');
        }

        // FIND BY bid: taaki stable public ID use ho
        const brand = await Brand.findOne({ bid: bid });
        
        if (!brand) {
            res.status(404);
            throw new Error('Brand not found');
        }

        const member = brand.members.find(m => m.user.toString() === userId.toString());

        if (!member || !allowedRoles.includes(member.role)) {
            res.status(403);
            throw new Error('Unauthorized: Insufficient permissions for this brand.');
        }

        req.brand = brand;
        req.userBrandRole = member.role; 
        next();
    });
};