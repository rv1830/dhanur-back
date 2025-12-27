import mongoose from 'mongoose';
import { generateUniquePublicId } from '../utils/idGenerator.js';

const CampaignSchema = new mongoose.Schema({
    cid: { type: String, unique: true, index: true },
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
    delete ret._id;
    delete ret.__v;
    return ret;
};
CampaignSchema.set('toJSON', { transform: transformResponse });
CampaignSchema.set('toObject', { transform: transformResponse });

CampaignSchema.pre('save', async function () {
    if (!this.cid) {
        this.cid = await generateUniquePublicId(this.constructor, 'CMP');
    }
});

export default mongoose.model('Campaign', CampaignSchema);