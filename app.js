const express = require('express');
const users = require('./routes/users');
const api = require('./routes/api');
const { validateToken } = require('./middlewares');
const jwt = require('jsonwebtoken');
const app = express();
const { ACCESS_TOKEN_SECRET } = require('./routes/env');
const { format } = require('morgan');

const optionsArray = [
    { method: "post", path: "/users/register", description: "Register, Required: email, name, password", example: { body: { email: "user@email.com", name: "user", password: "password" } } },
    { method: "post", path: "/users/login", description: "Login, Required: valid email and password", example: { body: { email: "user@email.com", password: "password" } } },
    { method: "post", path: "/users/token", description: "Renew access token, Required: valid refresh token", example: { headers: { token: "\*Refresh Token\*" } } },
    { method: "post", path: "/users/tokenValidate", description: "Access Token Validation, Required: valid access token", example: { headers: { Authorization: "Bearer \*Access Token\*" } } },
    { method: "get", path: "/api/v1/information", description: "Access user's information, Required: valid access token", example: { headers: { Authorization: "Bearer \*Access Token\*" } } },
    { method: "post", path: "/users/logout", description: "Logout, Required: access token", example: { body: { token: "\*Refresh Token\*" } } },
    { method: "get", path: "/api/v1/users", description: "Get users DB, Required: Valid access token of admin user", example: { headers: { authorization: "Bearer \*Access Token\*" } } }
  ]

app.use(express.json());
app.use('/api/v1', api);
app.use('/users', users);

app.options('/', validateToken, (req, res) => {
    const { token } = req;
    if(!token){
        const options = optionsArray.filter(option => (option.path.includes('login') || option.path.includes('register')));
        return res.json(options);
    }
    return jwt.verify(token, ACCESS_TOKEN_SECRET, (err, decoded) => {
        if(err){
            const options = 
                optionsArray.filter(
                    option => (option.path.includes('login')
                                || option.path.includes('register')
                                || option.path === '/users/token'));
            return res.json(options);
        }
        if(!decoded.isAdmin){
            for(let i = 0; i < optionsArray.length; i++){
                if(optionsArray[i].path === '/api/v1/users'){
                    optionsArray.splice(i, 1);
                }
            }
            return res.json(optionsArray);
        }
        res.json(optionsArray);
    });

});

app.use('*', (req, res) => {
    res.status(404).send('Not Found');
})


module.exports = app;