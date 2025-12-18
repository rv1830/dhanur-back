import mongoose from 'mongoose';
import { generateUniquePublicId } from '../utils/idGenerator.js';

const BrandSchema = new mongoose.Schema({
    bid: { type: String, unique: true, index: true }, // BR-12345678
    brandName: { type: String, required: true, trim: true },
    industry: { type: String, required: true },
    companyEmail: { type: String, required: true, lowercase: true },
    website: { type: String },
    logo: { type: String },
    description: { type: String },
    members: [{
        user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        role: { type: String, enum: ['BRAND ADMIN', 'MANAGER', 'EXECUTIVE'], default: 'EXECUTIVE' },
        joinedAt: { type: Date, default: Date.now }
    }],
    invitations: [{
        email: { type: String, lowercase: true, required: true },
        role: { type: String, enum: ['BRAND ADMIN', 'MANAGER', 'EXECUTIVE'] },
        token: { type: String, required: true },
        invitedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        createdAt: { type: Date, default: Date.now, expires: '7d' }
    }]
}, { timestamps: true });

// PRE-SAVE HOOK FOR BID
BrandSchema.pre('save', async function (next) {
    if (!this.bid) {
        this.bid = await generateUniquePublicId(this.constructor, 'BRAND');
    }
    next();
});

export default mongoose.model('Brand', BrandSchema);