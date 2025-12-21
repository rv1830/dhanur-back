import mongoose from 'mongoose';

const ConnectionSchema = new mongoose.Schema({
    brandId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'Brand', 
        required: true, 
        index: true 
    },
    influencerId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true, 
        index: true 
    },
    initiatedBy: { 
        type: String, 
        enum: ['BRAND', 'INFLUENCER'], 
        required: true 
    },
    status: { 
        type: String, 
        enum: ['PENDING', 'ACCEPTED', 'REJECTED', 'WITHDRAWN'], 
        default: 'PENDING' 
    },
    collabType: { 
        type: String, 
        enum: [
            'SPONSORSHIP',
            'BARTER',
            'PAID_COLLAB',
            'AMBASSADOR',
            'AFFILIATE',
            'EVENT',
            'UGC',
            'GIVEAWAY',
            'CO_BRANDING',
            'GENERAL',
            'OTHER'
        ],
        default: 'GENERAL'
    },
    pitchMessage: { 
        type: String, 
        maxlength: 500, 
        trim: true 
    },
    lastActionAt: { type: Date, default: Date.now }
}, { 
    timestamps: true 
});

ConnectionSchema.index({ brandId: 1, influencerId: 1 }, { unique: true });

export default mongoose.model('Connection', ConnectionSchema);