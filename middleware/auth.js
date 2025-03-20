const jwt = require('jsonwebtoken');
const { userInvalidTokens } = require('../db');
const config = require('../config');

async function ensureAuthenticated(req, res, next) {
    const accessToken = req.headers.authorization;

    if (!accessToken) {
        return res.status(401).json({ message: 'Access token not found' });
    }

    if (await userInvalidTokens.findOne({ accessToken })) {
        return res.status(401).json({ message: 'Access token invalid', code: 'AccessTokenInvalid' });
    }

    try {
        const decodedAccessToken = jwt.verify(accessToken, config.accessTokenSecret);
        
        req.accessToken = { value: accessToken, exp: decodedAccessToken.exp };
        req.user = { id: decodedAccessToken.userId };
        next();
    } catch (err) {
        if (err instanceof jwt.TokenExpiredError) {
            return res.status(401).json({ message: 'Access token expired', code: 'AccessTokenExpired' });
        } else if (err instanceof jwt.JsonWebTokenError) {
            return res.status(401).json({ message: 'Access token invalid', code: 'AccessTokenInvalid' });
        }
        return res.status(500).json({ message: err.message });
    }
}

module.exports = ensureAuthenticated;