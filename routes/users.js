const express = require('express');
const { users } = require('../db');
const ensureAuthenticated = require('../middleware/auth');

const router = express.Router();

router.get('/current', ensureAuthenticated, async (req, res) => {
    try {
        const user = await users.findOne({ _id: req.user.id });
        
        return res.status(200).json({
            id: user._id,
            name: user.name,
            email: user.email
        });
    } catch (err) {
        return res.status(500).json({ message: err.message });
    }
});

module.exports = router;