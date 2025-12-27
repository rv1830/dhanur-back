import mongoose from 'mongoose';
import { generateUniquePublicId } from '../utils/idGenerator.js';

const ApplicationSchema = new mongoose.Schema({
    appId: { type: String, unique: true, index: true },
    campaign: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'Campaign', 
        required: true 
    },
    influencer: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    message: { type: String, required: true },
    bidAmount: { type: Number },
    status: { 
        type: String, 
        enum: ['PENDING', 'SHORTLISTED', 'ACCEPTED', 'REJECTED'], 
        default: 'PENDING' 
    }
}, { timestamps: true });

ApplicationSchema.index({ campaign: 1, influencer: 1 }, { unique: true });

const transformResponse = (doc, ret) => {
    delete ret._id;
    delete ret.__v;
    return ret;
};
ApplicationSchema.set('toJSON', { transform: transformResponse });
ApplicationSchema.set('toObject', { transform: transformResponse });

ApplicationSchema.pre('save', async function () {
    if (!this.appId) {
        this.appId = await generateUniquePublicId(this.constructor, 'APP');
    }
});

export default mongoose.model('Application', ApplicationSchema);