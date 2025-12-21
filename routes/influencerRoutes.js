import express from 'express';
import { 
    searchInfluencers, 
    getInfluencerProfile 
} from '../controllers/influencerController.js';
import { protect } from '../middleware/authMiddleware.js';

const router = express.Router();

router.get('/search',protect, searchInfluencers);
router.get('/:uid',protect, getInfluencerProfile);

export default router;