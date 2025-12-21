import asyncHandler from 'express-async-handler';
import User from '../models/User.js';
import SocialAccount from '../models/SocialAccount.js';
import YouTubeAnalytics from '../models/YouTubeAnalytics.js';
import InstagramAnalytics from '../models/InstagramAnalytics.js';
import FacebookAnalytics from '../models/FacebookAnalytics.js';

// =================================================================
// 🔍 SEARCH API (Lightweight - Card View Data Only)
// =================================================================
export const searchInfluencers = asyncHandler(async (req, res) => {
    const { 
        keyword, platform, minFollowers, maxFollowers, gender, 
        page = 1, limit = 10 
    } = req.query;

    const pageNum = Number(page);
    const limitNum = Number(limit);
    const skip = (pageNum - 1) * limitNum;

    const pipeline = [];

    // 1. Match Active Influencers Only
    const matchStage = {
        userType: 'INFLUENCER',
        onboardingComplete: true,
        profileComplete: true
    };

    // Text Search (Name or Bio)
    if (keyword) {
        matchStage.$or = [
            { name: { $regex: keyword, $options: 'i' } },
            { 'profile.bio': { $regex: keyword, $options: 'i' } }
        ];
    }
    
    // Gender Filter
    if (gender) matchStage.gender = gender.toUpperCase();

    pipeline.push({ $match: matchStage });

    // 2. Lookup Social Accounts
    pipeline.push({
        $lookup: {
            from: 'socialaccounts', // Collection name in MongoDB
            localField: '_id',
            foreignField: 'userId',
            as: 'socialAccounts'
        }
    });

    // 3. Platform Filter (e.g., Only show influencers with YouTube)
    if (platform) {
        pipeline.push({
            $match: { 'socialAccounts.platform': platform.toUpperCase() }
        });
    }

    // 4. Calculate Total Reach (Sum of followers)
    pipeline.push({
        $addFields: {
            totalReach: { $sum: '$socialAccounts.followersCount' }
        }
    });

    // 5. Followers Range Filter
    if (minFollowers || maxFollowers) {
        const followerMatch = {};
        if (minFollowers) followerMatch.$gte = Number(minFollowers);
        if (maxFollowers) followerMatch.$lte = Number(maxFollowers);
        pipeline.push({ $match: { totalReach: followerMatch } });
    }

    // 6. PROJECTION (Clean Data, No IDs)
    pipeline.push({
        $project: {
            _id: 0, // ❌ Removing Mongo ID
            uid: 1,
            name: 1,
            profilePicture: 1,
            gender: 1,
            bio: '$profile.bio',
            totalReach: 1,
            socials: {
                $map: {
                    input: "$socialAccounts",
                    as: "acc",
                    in: {
                        platform: "$$acc.platform",
                        followers: "$$acc.followersCount",
                        handle: "$$acc.profileName"
                    }
                }
            }
        }
    });

    // 7. Pagination Facet
    pipeline.push({
        $facet: {
            metadata: [{ $count: "total" }],
            data: [{ $skip: skip }, { $limit: limitNum }]
        }
    });

    const result = await User.aggregate(pipeline);
    const influencers = result[0].data;
    const total = result[0].metadata[0] ? result[0].metadata[0].total : 0;

    res.json({
        success: true,
        page: pageNum,
        totalPages: Math.ceil(total / limitNum),
        totalInfluencers: total,
        influencers
    });
});


// =================================================================
// 👤 GET FULL PROFILE (Detail View - No Phone, Clickable Links, 24h Data)
// =================================================================
export const getInfluencerProfile = asyncHandler(async (req, res) => {
    const { uid } = req.params;

    // 1. Fetch User (Excluding sensitive info like phone, id, tokens)
    const user = await User.findOne({ uid, userType: 'INFLUENCER' })
        .select('uid name email profile profilePicture gender dateOfBirth createdAt -_id')
        .lean();

    if (!user) {
        res.status(404);
        throw new Error('Influencer not found.');
    }

    // 2. Fetch Social Accounts (Need internal _id for lookup)
    const userInternal = await User.findOne({ uid }).select('_id');
    const socialAccounts = await SocialAccount.find({ userId: userInternal._id }).lean();

    // 3. Process Each Platform
    const detailedSocials = await Promise.all(socialAccounts.map(async (acc) => {
        let latestAnalytics = null;
        let profileUrl = '';

        // Generate Clickable Profile Link
        switch (acc.platform) {
            case 'YOUTUBE':
                profileUrl = `https://youtube.com/${acc.profileName.startsWith('@') ? acc.profileName : '@' + acc.profileName}`;
                // Fetch Latest Analytics (Only 1 record)
                latestAnalytics = await YouTubeAnalytics.findOne({ socialAccountId: acc._id })
                    .sort({ date: -1 }) // Newest first
                    .select('-_id -socialAccountId -__v -createdAt -updatedAt') // Clean response
                    .lean();
                break;

            case 'INSTAGRAM':
                profileUrl = `https://instagram.com/${acc.profileName}`;
                latestAnalytics = await InstagramAnalytics.findOne({ socialAccountId: acc._id })
                    .sort({ date: -1 })
                    .select('-_id -socialAccountId -__v -createdAt -updatedAt')
                    .lean();
                break;

            case 'FACEBOOK':
                profileUrl = `https://facebook.com/${acc.platformId}`; 
                latestAnalytics = await FacebookAnalytics.findOne({ socialAccountId: acc._id })
                    .sort({ date: -1 })
                    .select('-_id -socialAccountId -__v -createdAt -updatedAt')
                    .lean();
                break;
            
            case 'LINKEDIN':
                profileUrl = `https://linkedin.com/in/${acc.profileName}`;
                break;

            default:
                profileUrl = '#';
        }

        return {
            platform: acc.platform,
            handle: acc.profileName,
            profileUrl: profileUrl, // ✅ Link Added
            stats: {
                followers: acc.followersCount,
                totalViews: acc.totalViews,
                totalVideos: acc.totalVideos,
                lastSynced: acc.lastSynced
            },
            latestInsights: latestAnalytics || "No recent data" // ✅ Only Last 24h Data
        };
    }));

    // 4. Final Response
    res.json({
        success: true,
        profile: {
            uid: user.uid,
            name: user.name,
            bio: user.profile?.bio || "",
            profilePicture: user.profilePicture,
            gender: user.gender,
            email: user.email, // Business contact email
            joinedAt: user.createdAt,
        },
        socialPlatforms: detailedSocials
    });
});