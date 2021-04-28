const { ACCESS_TOKEN_SECRET } = require('../routes/env');
const jwt = require('jsonwebtoken');

const validateToken = (req, res, next) =>{
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.slice(7);
    if(req.route.methods.options){
        req.token = token;
        next();
    }
    if(!token) return res.status(401).send('Access Token Required');
    return jwt.verify(token, ACCESS_TOKEN_SECRET, (err, decoded) => {
        if(err){
            return res.status(403).send('Invalid Access Token');
        }
        req.user = decoded;
        next();
    });
}

module.exports = { validateToken };