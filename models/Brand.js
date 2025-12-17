import mongoose from 'mongoose';

const BrandSchema = new mongoose.Schema({
    brandName: { type: String, required: true, trim: true },
    industry: { type: String, required: true },
    companyEmail: { type: String, required: true, lowercase: true },
    website: { type: String },
    logo: { type: String },
    description: { type: String },
    
    // Team Management
    members: [{
        user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        role: { 
            type: String, 
            enum: ['BRAND ADMIN', 'MANAGER', 'EXECUTIVE'], 
            default: 'EXECUTIVE' 
        },
        joinedAt: { type: Date, default: Date.now }
    }],

    // Pending Invites
    invitations: [{
        email: { type: String, lowercase: true, required: true },
        role: { type: String, enum: ['BRAND ADMIN', 'MANAGER', 'EXECUTIVE'] },
        token: { type: String, required: true }, // Unique token for the link
        invitedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        createdAt: { type: Date, default: Date.now, expires: '7d' } // 7 din mein expire
    }]
}, { timestamps: true });

export default mongoose.model('Brand', BrandSchema);