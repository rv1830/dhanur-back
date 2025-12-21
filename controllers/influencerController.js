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

    // 🔥 My Brand ID Logic (Agar user Brand hai)
    let myBrandId = null;
    if (req.user && req.user.userType === 'BRAND') {
        const brand = await Brand.findOne({ 'members.user': req.user._id }).select('_id');
        if (brand) myBrandId = brand._id;
    }

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

    if (keyword) {
        matchStage.$or = [
            { name: { $regex: keyword, $options: 'i' } },
            { 'profile.bio': { $regex: keyword, $options: 'i' } }
        ];
    }
    
    if (gender) matchStage.gender = gender.toUpperCase();

    pipeline.push({ $match: matchStage });

    // 2. Lookup Social Accounts
    pipeline.push({
        $lookup: {
            from: 'socialaccounts',
            localField: '_id',
            foreignField: 'userId',
            as: 'socialAccounts'
        }
    });

    if (platform) {
        pipeline.push({
            $match: { 'socialAccounts.platform': platform.toUpperCase() }
        });
    }

    // 4. Calculate Total Reach
    pipeline.push({
        $addFields: {
            totalReach: { $sum: '$socialAccounts.followersCount' }
        }
    });

    if (minFollowers || maxFollowers) {
        const followerMatch = {};
        if (minFollowers) followerMatch.$gte = Number(minFollowers);
        if (maxFollowers) followerMatch.$lte = Number(maxFollowers);
        pipeline.push({ $match: { totalReach: followerMatch } });
    }

    // =========================================================
    // 🔗 CONNECTION STATUS LOGIC (NEW ADDITION)
    // =========================================================
    if (myBrandId) {
        pipeline.push({
            $lookup: {
                from: 'connections',
                let: { influencerInternalId: '$_id' }, // Influencer ki Internal ID
                pipeline: [
                    {
                        $match: {
                            $expr: {
                                $and: [
                                    { $eq: ['$brandId', myBrandId] },             // My Brand Match
                                    { $eq: ['$influencerId', '$$influencerInternalId'] } // Influencer Match
                                ]
                            }
                        }
                    },
                    { $project: { status: 1 } } // Sirf status uthao
                ],
                as: 'connectionInfo'
            }
        });
    }

    // 6. PROJECTION (Clean Data)
    pipeline.push({
        $project: {
            _id: 0,
            uid: 1,
            name: 1,
            profilePicture: 1,
            gender: 1,
            bio: '$profile.bio',
            totalReach: 1,
            
            // ✅ Connection Status
            connectionStatus: { 
                $ifNull: [{ $arrayElemAt: ["$connectionInfo.status", 0] }, "NOT_CONNECTED"] 
            },

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