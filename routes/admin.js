const express = require('express');
const ensureAuthenticated = require('../middleware/auth');
const authorize = require('../middleware/authorize');

const router = express.Router();

router.get('/', ensureAuthenticated, authorize(['admin']), async (req, res) => {
    return res.status(200).json({ message: 'Only admins can access this route!' });
});

router.get('/moderator', ensureAuthenticated, authorize(['admin', 'moderator']), async (req, res) => {
    return res.status(200).json({ message: 'Only admins and moderators can access this route!' });
});

module.exports = router;