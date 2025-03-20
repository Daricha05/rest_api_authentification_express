const { users } = require('../db');

function authorize(roles = []) {
    return async function (req, res, next) {
        const user = await users.findOne({ _id: req.user.id });

        if (!user || !roles.includes(user.role)) {
            return res.status(403).json({ message: 'Access denied' });
        }

        next();
    };
}

module.exports = authorize;