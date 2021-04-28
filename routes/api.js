const { Router } = require('express');
const { validateToken } = require('../middlewares');
const { INFORMATION, USERS } = require('../helpers');
const api = Router();

api.get('/information', validateToken, (req, res) => {
    const { email } = req.user;
    const info = INFORMATION.find(info => info.email === email);
    res.status(200).json([info]);
});

api.get('/users', validateToken, (req, res) => {
    const { user: { isAdmin }} = req;
    if(!isAdmin) return res.status(403).json('Invalid Access Token');
    
    res.status(200).json(USERS);
});

module.exports = api;