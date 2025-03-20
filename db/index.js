const Datastore = require('nedb-promises');

const users = Datastore.create('users.db');
const userRefreshTokens = Datastore.create('UserRefreshTokens.db');
const userInvalidTokens = Datastore.create('UserInvalidTokens.db');

module.exports = {
    users,
    userRefreshTokens,
    userInvalidTokens
};