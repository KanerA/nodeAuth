const { Router } = require('express');
const jwt = require('jsonwebtoken');
const { hashSync, compare } = require('bcrypt');
const { USERS, INFORMATION, REFRESHTOKENS } = require('../helpers');
const { ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET } = require('./env.js');
const { validateToken } = require('../middlewares');
const users = Router();

// require('crypto').randomBytes(64).toString('hex')


users.post('/register', (req, res) => {
    const { email, name, password } = req.body;
    const userExist = USERS.find( user => email === user.email);
    if(userExist) return res.status(409).send('user already exists');
    const hashedPW = hashSync(password, 10);
    USERS.push({
        email,
        name,
        password: hashedPW,
        isAdmin: false,
    });

    INFORMATION.push({
        email,
        info: `${name} info`,
    }),

    res.status(201).send('Register Success')
});

users.post('/login', async (req, res) => {
    const {body: { email, password }} = req;
    const user = USERS.find(entry => entry.email === email);

    if(!user) return res.status(404).send('cannot find user');
    try{
        const dataToken = {
            name: user.name,
            email: user.email,
            isAdmin: user.isAdmin,
        };
        const refreshToken = jwt.sign(dataToken, REFRESH_TOKEN_SECRET);
        const accessToken = jwt.sign(dataToken, ACCESS_TOKEN_SECRET, {
            expiresIn: '10s'
        });
        const isPasswordCorrect = await compare(password, user.password);
        if(!isPasswordCorrect) return res.status(403).send('User or Password incorrect');

    REFRESHTOKENS.push(refreshToken);

    res.status(200).json({
        accessToken,
         refreshToken,
         email,
         name:user.name,
         isAdmin:user.isAdmin
        });

    } catch(err){
        console.log(err);
        res.sendStatus(500);
    }
});

users.post('/tokenValidate', validateToken, (req, res) => {
    res.json({ valid: true });
});

users.post('/token', (req, res) => {
    const { token } = req.body;
    if(!token) return res.status(401).send('Refresh Token Required');
    
    if(!REFRESHTOKENS.includes(token)) return res.status(403).json('Invalid Refresh Token');
    
    jwt.verify(token, REFRESH_TOKEN_SECRET, (err, decoded) => {
        if(err) return res.status(403).json('Invalid Refresh Token');
        const accessToken = jwt.sign(decoded, ACCESS_TOKEN_SECRET, {
            expiresIn: '30s',
        });
        return res.status(200).json({ accessToken });
    });
});

users.post('/logout', (req, res) => {
    const { token } = req.body;
    if(!token) return res.status(400).send('Refresh Token Required');
    const refreshTokenIndex = REFRESHTOKENS.findIndex(rToken => rToken === token);
    if(refreshTokenIndex === -1) return res.status(400).send('Invalid Refresh Token');

    REFRESHTOKENS.splice(refreshTokenIndex, 1);
    return res.send('User Logged Out Successfully');

});

module.exports = users;