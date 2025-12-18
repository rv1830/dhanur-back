import mongoose from 'mongoose';
import { generateUniquePublicId } from '../utils/idGenerator.js';

const BrandSchema = new mongoose.Schema({
    bid: { type: String, unique: true, index: true }, // Stable Public ID: BR-12345678
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
}, { 
    timestamps: true 
});

// =================================================================
// 🛡️ GLOBAL RESPONSE TRANSFORMER (Removes _id and __v)
// =================================================================
const transformResponse = (doc, ret) => {
    delete ret._id;  // MongoDB Internal ID hide karega
    delete ret.__v;  // Version key hide karega
    
    // Members ke andar se bhi internal _id hata dega
    if (ret.members) {
        ret.members.forEach(m => delete m._id);
    }
    
    // Invitations ke andar se bhi internal _id hata dega
    if (ret.invitations) {
        ret.invitations.forEach(i => delete i._id);
    }
    
    return ret;
};

BrandSchema.set('toJSON', { transform: transformResponse });
BrandSchema.set('toObject', { transform: transformResponse });

// =================================================================
// 🆔 PRE-SAVE HOOK FOR UNIQUE BID (Modern Async Way)
// =================================================================
BrandSchema.pre('save', async function () {
    if (!this.bid) {
        // generateUniquePublicId function database mein check karke 'BR-XXXX' dega
        this.bid = await generateUniquePublicId(this.constructor, 'BRAND');
    }
});

export default mongoose.model('Brand', BrandSchema);