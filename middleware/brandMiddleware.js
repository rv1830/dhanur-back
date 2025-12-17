import asyncHandler from 'express-async-handler';
import Brand from '../models/Brand.js';

export const checkBrandRole = (allowedRoles) => {
    return asyncHandler(async (req, res, next) => {
        // brandId params se ya body se uthayein
        const brandId = req.params.brandId || req.body.brandId;
        const userId = req.user._id;

        const brand = await Brand.findById(brandId);
        if (!brand) {
            res.status(404);
            throw new Error('Brand not found');
        }

        const member = brand.members.find(m => m.user.toString() === userId.toString());

        if (!member || !allowedRoles.includes(member.role)) {
            res.status(403);
            throw new Error('Unauthorized: You do not have permission for this action.');
        }

        req.brand = brand;
        next();
    });
};