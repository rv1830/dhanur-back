import asyncHandler from 'express-async-handler';
import Connection from '../models/Connection.js';
import Brand from '../models/Brand.js';
import User from '../models/User.js';

export const manageConnection = asyncHandler(async (req, res) => {
    const { targetId, action, collabType, pitchMessage } = req.body; 
    
    const user = req.user;
    let brandId, influencerId, initiatedBy;

    if (user.userType === 'BRAND') {
        const myBrand = await Brand.findOne({ 'members.user': user._id });
        if (!myBrand) { res.status(403); throw new Error('Access Denied: Brand profile required.'); }

        const targetUser = await User.findOne({ uid: targetId });
        if (!targetUser) { res.status(404); throw new Error('Influencer not found.'); }

        if (targetUser.userType !== 'INFLUENCER') {
            res.status(400); throw new Error('Brands can only connect with Influencers.');
        }

        brandId = myBrand._id;
        influencerId = targetUser._id;
        initiatedBy = 'BRAND';
    } 
    else if (user.userType === 'INFLUENCER') {
        if (!targetId.startsWith('BR-') && !targetId.startsWith('br-')) {
             res.status(400); throw new Error('Influencers can only connect with Brands using Brand ID.');
        }

        const targetBrand = await Brand.findOne({ bid: targetId });
        if (!targetBrand) { res.status(404); throw new Error('Brand not found.'); }

        influencerId = user._id;
        brandId = targetBrand._id;
        initiatedBy = 'INFLUENCER';
    } 
    else {
        res.status(403); throw new Error('Invalid User Type.');
    }

    let connection = await Connection.findOne({ brandId, influencerId });

    const validCollabTypes = [
        'SPONSORSHIP', 'BARTER', 'PAID_COLLAB', 'AMBASSADOR', 
        'AFFILIATE', 'EVENT', 'UGC', 'GIVEAWAY', 'CO_BRANDING', 
        'GENERAL', 'OTHER'
    ];

    if (action === 'CONNECT') {
        const typeToSave = validCollabTypes.includes(collabType) ? collabType : 'OTHER';
        const msgToSave = pitchMessage ? pitchMessage.trim() : '';

        if (connection) {
            if (['REJECTED', 'WITHDRAWN'].includes(connection.status)) {
                connection.status = 'PENDING';
                connection.initiatedBy = initiatedBy;
                connection.collabType = typeToSave;
                connection.pitchMessage = msgToSave;
                connection.lastActionAt = Date.now();
                await connection.save();
                return res.json({ success: true, status: 'PENDING', message: 'Request sent again.' });
            } 
            else {
                return res.status(400).json({ success: false, message: `Connection is already ${connection.status}` });
            }
        } else {
            connection = await Connection.create({
                brandId,
                influencerId,
                initiatedBy,
                status: 'PENDING',
                collabType: typeToSave,
                pitchMessage: msgToSave
            });
            return res.status(201).json({ success: true, status: 'PENDING', message: 'Proposal sent successfully.' });
        }
    }

    else if (action === 'WITHDRAW') {
        if (!connection) { res.status(404); throw new Error('No connection found.'); }
        connection.status = 'WITHDRAWN';
        connection.lastActionAt = Date.now();
        await connection.save();
        return res.json({ success: true, status: 'WITHDRAWN', message: 'Connection withdrawn.' });
    }

    else if (action === 'ACCEPT' || action === 'REJECT') {
        if (!connection) { res.status(404); throw new Error('No request found.'); }
        
        if (connection.initiatedBy === initiatedBy) {
             res.status(400); throw new Error('You cannot accept your own request.');
        }

        connection.status = action === 'ACCEPT' ? 'ACCEPTED' : 'REJECTED';
        connection.lastActionAt = Date.now();
        await connection.save();
        
        return res.json({ success: true, status: connection.status, message: `Request ${action.toLowerCase()}ed.` });
    }

    else {
        res.status(400); throw new Error('Invalid Action.');
    }
});

export const getMyConnections = asyncHandler(async (req, res) => {
    const { status } = req.query;
    const user = req.user;
    let query = {};

    if (user.userType === 'BRAND') {
        const myBrand = await Brand.findOne({ 'members.user': user._id });
        if (!myBrand) { res.status(404); throw new Error('Brand profile not found'); }
        
        query = { brandId: myBrand._id };
        if (status) query.status = status;

        const connections = await Connection.find(query)
            .populate('influencerId', 'uid name profilePicture email')
            .sort({ lastActionAt: -1 });

        res.json({ success: true, count: connections.length, connections });
    } 
    else if (user.userType === 'INFLUENCER') {
        query = { influencerId: user._id };
        if (status) query.status = status;

        const connections = await Connection.find(query)
            .populate('brandId', 'bid brandName logo website industry')
            .sort({ lastActionAt: -1 });

        res.json({ success: true, count: connections.length, connections });
    } 
    else {
        res.status(400); throw new Error('Invalid User Type');
    }
});