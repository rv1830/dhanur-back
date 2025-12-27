import express from 'express';
import { 
    createCampaign, 
    getAllCampaigns, 
    getCampaignById, 
    updateCampaign, 
    deleteCampaign, 
    applyToCampaign, 
    getCampaignApplicants,
    updateApplicationStatus
} from '../controllers/campaignController.js';
import { protect, isBrand, isInfluencer } from '../middleware/authMiddleware.js';

const router = express.Router();

// Public Routes
router.get('/', getAllCampaigns);
router.get('/:cid', getCampaignById);

// Brand Routes (authorize('BRAND') ki jagah isBrand lagaya)
router.post('/', protect, isBrand, createCampaign);
router.put('/:cid', protect, isBrand, updateCampaign);
router.delete('/:cid', protect, isBrand, deleteCampaign);
router.get('/:cid/applications', protect, isBrand, getCampaignApplicants);
router.patch('/applications/:appId/status', protect, isBrand, updateApplicationStatus);

// Influencer Routes (authorize('INFLUENCER') ki jagah isInfluencer lagaya)
router.post('/:cid/apply', protect, isInfluencer, applyToCampaign);

export default router;