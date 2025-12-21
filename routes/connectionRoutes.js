import express from 'express';
import { 
    manageConnection, 
    getMyConnections 
} from '../controllers/connectionController.js';
import { protect } from '../middleware/authMiddleware.js';

const router = express.Router();

router.post('/manage',protect, manageConnection);
router.get('/',protect, getMyConnections);

export default router;