import mongoose from 'mongoose';

const MetaAnalyticsSchema = mongoose.Schema({
    socialAccountId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'SocialAccount',
        required: true,
    },
    // Meta से मिलने वाली तारीख (YYYY-MM-DD फॉर्मेट में स्टोर करें)
    date: { type: Date, required: true, index: true }, 

    // --- Instagram Metrics (IG Business Account) ---
    // Reach, Impressions और Profile Views जैसे मेट्रिक्स को Store करें
    reach: { type: Number, default: 0 },
    impressions: { type: Number, default: 0 },
    profileViews: { type: Number, default: 0 }, 
    
    // Engagement Metrics (API से मिलने पर)
    engagement: { type: Number, default: 0 },
    postReactions: { type: Number, default: 0 },

    // --- Facebook Page Metrics ---
    pageImpressions: { type: Number, default: 0 },
    pageEngagedUsers: { type: Number, default: 0 },
    pageViewsTotal: { type: Number, default: 0 },

    // Ensures only one record per account per day
    unique: ['socialAccountId', 'date']
}, { timestamps: true });

const MetaAnalytics = mongoose.model('MetaAnalytics', MetaAnalyticsSchema);
export default MetaAnalytics;