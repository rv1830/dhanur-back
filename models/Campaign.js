import mongoose from 'mongoose';

const CampaignSchema = new mongoose.Schema({
    // cid field removed
    brand: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'Brand', 
        required: true 
    },
    createdBy: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    title: { type: String, required: true, trim: true },
    description: { type: String, required: true },
    platform: { 
        type: String, 
        enum: ['INSTAGRAM', 'YOUTUBE', 'LINKEDIN', 'TWITTER', 'OTHER'], 
        required: true 
    },
    category: { type: String, required: true },
    requirements: { type: String },
    budgetType: { 
        type: String, 
        enum: ['FIXED', 'NEGOTIABLE', 'BARTER'], 
        default: 'FIXED' 
    },
    budgetAmount: { type: Number },
    status: { 
        type: String, 
        enum: ['ACTIVE', 'PAUSED', 'COMPLETED', 'CLOSED'], 
        default: 'ACTIVE' 
    },
    deadline: { type: Date, required: true },
}, { timestamps: true });

const transformResponse = (doc, ret) => {
    ret.id = ret._id; // _id ko id mein map kiya
    delete ret._id;   // _id remove kiya
    delete ret.__v;   // __v remove kiya
    return ret;
};
CampaignSchema.set('toJSON', { transform: transformResponse });
CampaignSchema.set('toObject', { transform: transformResponse });

// pre('save') hook removed

export default mongoose.model('Campaign', CampaignSchema);