import Campaign from '../models/Campaign.js';
import Application from '../models/Application.js';
import Brand from '../models/Brand.js';
import Connection from '../models/Connection.js';

// --- CREATE CAMPAIGN ---
export const createCampaign = async (req, res) => {
    try {
        const userId = req.user._id;
        const { brandId, title, description, platform, category, requirements, budgetType, budgetAmount, deadline } = req.body;

        if (!brandId) {
            return res.status(400).json({ message: "Brand ID is required." });
        }

        const brand = await Brand.findOne({ bid: brandId });

        if (!brand) {
            return res.status(404).json({ message: "Brand not found." });
        }

        const isMember = brand.members.some(member => member.user.toString() === userId.toString());

        if (!isMember) {
            return res.status(403).json({ message: "You are not authorized to create a campaign for this brand." });
        }

        const newCampaign = await Campaign.create({
            brand: brand._id,
            createdBy: userId,
            title,
            description,
            platform,
            category,
            requirements,
            budgetType,
            budgetAmount,
            deadline
        });

        res.status(201).json({ success: true, campaign: newCampaign });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// --- GET ALL CAMPAIGNS (Optimized & Paginated) ---
export const getAllCampaigns = async (req, res) => {
    try {
        // Extract query parameters with defaults
        const { 
            page = 1, 
            limit = 10, 
            search, 
            platform, 
            category, 
            minBudget, 
            maxBudget, 
            sortBy = 'newest' 
        } = req.query;

        // 1. Build Query Object
        let query = { status: 'ACTIVE' };

        // Search by Title (Case Insensitive)
        if (search) {
            query.title = { $regex: search, $options: 'i' };
        }

        // Exact Filters
        if (platform) query.platform = platform;
        if (category) query.category = category;

        // Budget Range Filter
        if (minBudget || maxBudget) {
            query.budgetAmount = {};
            if (minBudget) query.budgetAmount.$gte = Number(minBudget);
            if (maxBudget) query.budgetAmount.$lte = Number(maxBudget);
        }

        // 2. Pagination Calculation
        const pageNum = Number(page);
        const limitNum = Number(limit);
        const skip = (pageNum - 1) * limitNum;

        // 3. Sorting Logic
        let sortOptions = { createdAt: -1 }; // Default: Newest first
        if (sortBy === 'oldest') sortOptions = { createdAt: 1 };
        if (sortBy === 'highBudget') sortOptions = { budgetAmount: -1 };
        if (sortBy === 'lowBudget') sortOptions = { budgetAmount: 1 };

        // 4. Fetch Data & Count in Parallel (Faster performance)
        const [totalCampaigns, campaigns] = await Promise.all([
            Campaign.countDocuments(query),
            Campaign.find(query)
                .select('cid title brand platform category budgetType budgetAmount deadline -_id') // Lightweight response
                .populate('brand', 'brandName logo -_id') // Populating only necessary brand info
                .sort(sortOptions)
                .skip(skip)
                .limit(limitNum)
        ]);

        // 5. Send Response
        res.status(200).json({
            success: true,
            pagination: {
                total: totalCampaigns,
                page: pageNum,
                limit: limitNum,
                totalPages: Math.ceil(totalCampaigns / limitNum),
                hasNextPage: pageNum * limitNum < totalCampaigns,
                hasPrevPage: pageNum > 1
            },
            campaigns
        });

    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// --- GET CAMPAIGN BY ID ---
export const getCampaignById = async (req, res) => {
    try {
        const campaign = await Campaign.findOne({ cid: req.params.cid })
            .populate('brand', 'brandName logo description website');

        if (!campaign) {
            return res.status(404).json({ message: "Campaign not found" });
        }

        res.status(200).json({ success: true, campaign });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// --- UPDATE CAMPAIGN ---
export const updateCampaign = async (req, res) => {
    try {
        const userId = req.user._id;
        const campaign = await Campaign.findOne({ cid: req.params.cid });
        
        if (!campaign) return res.status(404).json({ message: "Campaign not found" });

        const brand = await Brand.findOne({ _id: campaign.brand, 'members.user': userId });
        if (!brand) {
            return res.status(403).json({ message: "Not authorized to update this campaign" });
        }

        const updatedCampaign = await Campaign.findOneAndUpdate(
            { cid: req.params.cid },
            req.body,
            { new: true, runValidators: true }
        );

        res.status(200).json({ success: true, campaign: updatedCampaign });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// --- DELETE CAMPAIGN ---
export const deleteCampaign = async (req, res) => {
    try {
        const userId = req.user._id;
        const campaign = await Campaign.findOne({ cid: req.params.cid });
        
        if (!campaign) return res.status(404).json({ message: "Campaign not found" });

        const brand = await Brand.findOne({ _id: campaign.brand, 'members.user': userId });
        if (!brand) {
            return res.status(403).json({ message: "Not authorized to delete this campaign" });
        }

        await campaign.deleteOne();
        await Application.deleteMany({ campaign: campaign._id });

        res.status(200).json({ success: true, message: "Campaign deleted successfully" });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// --- APPLY TO CAMPAIGN ---
export const applyToCampaign = async (req, res) => {
    try {
        const userId = req.user._id;
        const { cid } = req.params;
        const { message, bidAmount } = req.body;

        const campaign = await Campaign.findOne({ cid });
        if (!campaign) return res.status(404).json({ message: "Campaign not found" });

        if (campaign.status !== 'ACTIVE') {
            return res.status(400).json({ message: "This campaign is no longer accepting applications." });
        }

        const existingApp = await Application.findOne({ campaign: campaign._id, influencer: userId });
        if (existingApp) {
            return res.status(400).json({ message: "You have already applied to this campaign." });
        }

        const newApplication = await Application.create({
            campaign: campaign._id,
            influencer: userId,
            message,
            bidAmount
        });

        res.status(201).json({ success: true, message: "Applied successfully", application: newApplication });

    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// --- GET APPLICANTS ---
export const getCampaignApplicants = async (req, res) => {
    try {
        const { cid } = req.params;
        const userId = req.user._id;

        const campaign = await Campaign.findOne({ cid });
        if (!campaign) return res.status(404).json({ message: "Campaign not found" });

        const brand = await Brand.findOne({ _id: campaign.brand, 'members.user': userId });
        if (!brand) return res.status(403).json({ message: "Not authorized to view applicants" });

        const applications = await Application.find({ campaign: campaign._id })
            .populate('influencer', 'name email profilePicture profile.bio')
            .sort({ createdAt: -1 });

        res.status(200).json({ success: true, count: applications.length, applications });

    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// --- UPDATE APPLICATION STATUS ---
export const updateApplicationStatus = async (req, res) => {
    try {
        const { appId } = req.params;
        const { status } = req.body;
        const userId = req.user._id;

        const application = await Application.findOne({ appId })
            .populate({
                path: 'campaign',
                populate: { path: 'brand' }
            });

        if (!application) {
            return res.status(404).json({ message: "Application not found" });
        }

        const campaign = application.campaign;
        const brand = campaign.brand;

        const isMember = brand.members.some(member => member.user.toString() === userId.toString());
        if (!isMember) {
            return res.status(403).json({ message: "You are not authorized to manage this application." });
        }

        application.status = status;
        await application.save();

        if (status === 'ACCEPTED') {
            let collabType = 'GENERAL';
            if (campaign.budgetType === 'FIXED' || campaign.budgetType === 'NEGOTIABLE') collabType = 'PAID_COLLAB';
            if (campaign.budgetType === 'BARTER') collabType = 'BARTER';

            await Connection.findOneAndUpdate(
                { 
                    brandId: brand._id, 
                    influencerId: application.influencer 
                },
                {
                    $set: {
                        initiatedBy: 'BRAND',
                        status: 'ACCEPTED',
                        collabType: collabType,
                        pitchMessage: `Connection established via Campaign: ${campaign.title}`,
                        lastActionAt: new Date()
                    }
                },
                { new: true, upsert: true, setDefaultsOnInsert: true }
            );
        }

        res.status(200).json({ 
            success: true, 
            message: `Application status updated to ${status}`, 
            application 
        });

    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};