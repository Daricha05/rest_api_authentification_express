const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { authenticator } = require("otplib");
const qrcode = require("qrcode");
const crypto = require("crypto");
const NodeCache = require("node-cache");

const config = require("../config");
const { users, userRefreshTokens, userInvalidTokens } = require("../db");
const ensureAuthenticated = require("../middleware/auth");

const router = express.Router();
const cache = new NodeCache();

router.get("/", (req, res) => {
  res.send("REST API Authentification and Authorization");
});

router.post("/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password) {
      return res
        .status(422)
        .json({ message: "Veuillez remplir tous les champs." });
    }

    if (await users.findOne({ email: email })) {
      return res.status(409).json({ message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await users.insert({
      name,
      email,
      password: hashedPassword,
      role: role ?? "member",
      "2faEnable": false,
      "2faSecret": null,
    });

    return res.status(201).json({
      message: "User registered successfully",
      id: newUser._id,
    });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

router.post("/login", async (req, res) => {
  try {
          const { email, password } = req.body;
  
          if (!email || !password) {
              return res.status(422).json({ message: 'Please fill in all fields' })
          }
  
          const user = await users.findOne({ email });
  
          if (!user) {
              return res.status(401).json({ message: 'Email or password is invalid' })
          }
  
          const passwordMatch = await bcrypt.compare(password, user.password)
  
          if (!passwordMatch) {
              return res.status(401).json({ message: 'Email or password is invalid' })
          }
  
          if (user['2faEnable']) {
              const tempToken = crypto.randomUUID()
  
              cache.set(config.cacheTemporaryTokenPrefix + tempToken, user._id, config.cacheTemporaryTokenExpiresSeconds)
  
              return res.status(200).json({ tempToken, expiresInSeconds: config.cacheTemporaryTokenExpiresSeconds })
          } else {
  
              const accessToken = jwt.sign({ userId: user._id }, config.accessTokenSecret, { subject: 'accessApi', expiresIn: config.accessTokenExpiresIn })
  
              // REFRESH TOKEN
              const refreshToken = jwt.sign({ userId: user._id }, config.refreshTokenSecret, { subject: 'refreshToken', expiresIn: config.refreshTokenExpiresIn })
  
              await userRefreshTokens.insert({
                  refreshToken,
                  userId: user._id
              })
  
              return res.status(200).json({
                  id: user._id,
                  name: user.name,
                  email: user.email,
                  accessToken,
                  refreshToken
              })
          }
  
      } catch (err) {
          return res.status(500).json({ message: err.message })
      }
});

router.post("/login/2fa", async (req, res) => {
  try {
          const { tempToken, totp } = req.body
  
          if (!tempToken || !totp) {
              return res.status(422).json({ message: "Please fill in all fields (tempToken, totp)" })
          }
  
          const userId = cache.get(config.cacheTemporaryTokenPrefix + tempToken)
  
          if (!userId) {
              return res.status(401).json({ message: 'The provided temporary token is incorrect or expired' })
          }
  
          const user = await users.findOne({ _id: userId })
  
          const verified = authenticator.check(totp, user['2faSecret'])
  
          if (!verified) {
              return res.status(401).json({ message: 'The provided TOTP is incorrect or expired' })
          }
  
          const accessToken = jwt.sign({ userId: user._id }, config.accessTokenSecret, { subject: 'accessApi', expiresIn: config.accessTokenExpiresIn })
  
          const refreshToken = jwt.sign({ userId: user._id }, config.refreshTokenSecret, { subject: 'refreshToken', expiresIn: config.refreshTokenExpiresIn })
  
          await userRefreshTokens.insert({
              refreshToken,
              userId: user._id
          })
  
          return res.status(200).json({
              id: user._id,
              name: user.name,
              email: user.email,
              accessToken,
              refreshToken
          })
  
      } catch (error) {
          return res.status(500).json({ message: error.message })
      }
});

router.post("/refresh-token", async (req, res) => {
  try {
          const { refreshToken } = req.body
  
          if (!refreshToken) {
              return res.status(401).json({ message: 'Refresh token not found' })
          }
  
          const decodedRefreshToken = jwt.verify(refreshToken, config.refreshTokenSecret)
  
          const userRefreshToken = await userRefreshTokens.findOne({ refreshToken, userId: decodedRefreshToken.userId })
  
          if (!userRefreshToken) {
              return res.status(401).json({ message: "Refresh token invalid or expired" })
          }
  
          await userRefreshTokens.remove({ _id: userRefreshToken._id })
          await userRefreshTokens.compactDatafile()
  
          const accessToken = jwt.sign({ userId: decodedRefreshToken.userId }, config.accessTokenSecret, { subject: 'accessApi', expiresIn: config.accessTokenExpiresIn })
  
          // REFRESH TOKEN
          const newRefreshToken = jwt.sign({ userId: decodedRefreshToken.userId }, config.refreshTokenSecret, { subject: 'refreshToken', expiresIn: config.refreshTokenExpiresIn })
  
          await userRefreshTokens.insert({
              refreshToken: newRefreshToken,
              userId: decodedRefreshToken.userId
          })
  
          return res.status(200).json({
              accessToken,
              refreshToken: newRefreshToken
          })
      } catch (err) {
          if (err instanceof jwt.TokenExpiredError || err instanceof jwt.TokenExpiredError) {
              return res.status(401).json({ message: "Refresh token invalid or expired" })
          }
  
          return res.status(500).json({ message: err.message })
      }
});

router.get("/2fa/generate", ensureAuthenticated, async (req, res) => {
  try {
          const user = await users.findOne({ _id: req.user.id })
  
          const secret = authenticator.generateSecret()
          const uri = authenticator.keyuri(user.email, 'richard.io', secret)
  
          await users.update({ _id: req.user.id }, { $set: { '2faSecret': secret } })
          await users.compactDatafile()
  
          const qrCode = await qrcode.toBuffer(uri, { type: 'image/png', margin: 1 })
  
          res.setHeader('Content-Disposition', 'attachment; filename=qrcode.png')
          return res.status(200).type('image/png').send(qrCode)
  
      } catch (err) {
          return res.status(500).json({ message: err.message })
      }
});

router.get("/2fa/validate", ensureAuthenticated, async (req, res) => {
  try {
          const { totp } = req.body
  
          if (!totp) {
              return res.status(422).json({ message: 'TOTP is required' })
          }
  
          const user = await users.findOne({ _id: req.user.id })
  
          const verified = authenticator.check(totp, user['2faSecret'])
  
          if (!verified) {
              return res.status(400).json({ message: 'TOTP is not correst or expired' })
          }
  
          await users.update({ _id: req.user.id }, { $set: { '2faEnable': true } })
          await users.compactDatafile()
  
          return res.status(200).json({ message: 'TOTP validated successfully' })
  
      } catch (err) {
          return res.status(500).json({ message: err.message })
      }
});

router.post("/logout", ensureAuthenticated, async (req, res) => {
    try {
        await userRefreshTokens.removeMany({ userId: req.user.id })
        await userRefreshTokens.compactDatafile()

        await userInvalidTokens.insert({
            accessToken: req.accessToken.value,
            userId: req.user.id,
            expirationTime: req.accessToken.exp
        })

        return res.status(204).send()

    } catch (err) {
        return res.status(500).json({ message: "Ici " + err.message })
    }
});

module.exports = router;
