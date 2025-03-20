const request = require('supertest');
const app = require('../app');
const { users } = require('../db');

describe('Users Routes', () => {
    let accessToken;

    beforeEach(async () => {
        await users.remove({}, { multi: true });
        
        // Créer un utilisateur et obtenir un token
        const registerRes = await request(app)
            .post('/api/auth/register')
            .send({
                name: 'Test User',
                email: 'test@example.com',
                password: 'password123'
            });

        const loginRes = await request(app)
            .post('/api/auth/login')
            .send({
                email: 'test@example.com',
                password: 'password123'
            });

        accessToken = loginRes.body.accessToken;
    });

    describe('GET /api/users/current', () => {
        it('should return current user info with valid token', async () => {
            const res = await request(app)
                .get('/api/users/current')
                .set('Authorization', accessToken);

            expect(res.statusCode).toBe(200);
            expect(res.body).toHaveProperty('id');
            expect(res.body).toHaveProperty('name', 'Test User');
            expect(res.body).toHaveProperty('email', 'test@example.com');
        });

        it('should reject request without token', async () => {
            const res = await request(app)
                .get('/api/users/current');

            expect(res.statusCode).toBe(401);
            expect(res.body).toHaveProperty('message', 'Access token not found');
        });
    });
});