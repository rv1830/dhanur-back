// --- models/FacebookAnalytics.js (NEW) ---
import mongoose from 'mongoose';

const FacebookAnalyticsSchema = mongoose.Schema({
    socialAccountId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'SocialAccount',
        required: true,
    },
    date: { type: Date, required: true, index: true }, 

    // --- Facebook Page Metrics ---
    pageImpressions: { type: Number, default: 0 },
    pageEngagedUsers: { type: Number, default: 0 },
    pageViewsTotal: { type: Number, default: 0 },
    pageFanCount: { type: Number, default: 0 }, // Daily Fan Count (if obtainable)
    
    // Ensures only one record per account per day
    unique: ['socialAccountId', 'date']
}, { timestamps: true });

const FacebookAnalytics = mongoose.model('FacebookAnalytics', FacebookAnalyticsSchema);
export default FacebookAnalytics;