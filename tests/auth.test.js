const request = require('supertest');
const app = require('../app');
const { users, userRefreshTokens, userInvalidTokens } = require('../db');


/**
 * Nettoyage avant chaque test
 * Cette fonction s'exécute avant chaque test pour garantir un état propre
 */
beforeEach(async () => {
    await users.remove({}, { multi: true }); // Supprime tous les documents de la collection users
    await userRefreshTokens.remove({}, { multi: true }); // Supprime tous les refresh tokens
    await userInvalidTokens.remove({}, { multi: true }); // Supprime tous les tokens invalidés
});

describe('Auth Routes', () => {
    describe('POST /api/auth/register', () => {
        // Vérifie qu'un nouvel utilisateur peut s'enregistrer
        it('should register a new user', async () => {
            // Envoie une requête POST à la route /api/auth/register
            const res = await request(app)
                .post('/api/auth/register')
                .send({
                    name: 'Test User',
                    email: 'test@example.com',
                    password: 'password123'
                });

            expect(res.statusCode).toBe(201);
            expect(res.body).toHaveProperty('message', 'User registered successfully');
            expect(res.body).toHaveProperty('id');
        });

        // Vérifie le rejet d'un email déjà utilisé
        it('should reject duplicate email', async () => {
            // Première inscription pour créer un utilisateur
            await request(app)
                .post('/api/auth/register')
                .send({
                    name: 'Test User',
                    email: 'test@example.com',
                    password: 'password123'
                });

            // Deuxième tentative avec le même email
            const res = await request(app)
                .post('/api/auth/register')
                .send({
                    name: 'Test User 2',
                    email: 'test@example.com',
                    password: 'password456'
                });

            expect(res.statusCode).toBe(409);
            expect(res.body).toHaveProperty('message', 'Email already exists');
        });
    });

    describe('POST /api/auth/login', () => {
        // Vérifie la connexion d'un utilisateur existant
        it('should login existing user', async () => {
            // Crée un utilisateur
            await request(app)
                .post('/api/auth/register')
                .send({
                    name: 'Test User',
                    email: 'test@example.com',
                    password: 'password123'
                });

            // Tente de se connecter avec les mêmes identifiants
            const res = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'test@example.com',
                    password: 'password123'
                });

            expect(res.statusCode).toBe(200);
            expect(res.body).toHaveProperty('accessToken');
            expect(res.body).toHaveProperty('refreshToken');
            expect(res.body).toHaveProperty('id');
            expect(res.body).toHaveProperty('name', 'Test User');
            expect(res.body).toHaveProperty('email', 'test@example.com');
        });

        // Vérifie le rejet d'identifiants invalides
        it('should reject invalid credentials', async () => {
            // Tente de se connecter sans utilisateur existant
            const res = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'test@example.com',
                    password: 'wrongpassword'
                });

            expect(res.statusCode).toBe(401);
            expect(res.body).toHaveProperty('message', 'Email or password is invalid');
        });
    });
});