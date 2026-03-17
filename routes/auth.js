var express = require("express");
var router = express.Router();
let userController = require('../controllers/users')
let { RegisterValidator, validationResult } = require('../utils/validatorHandler')
let { CheckLogin } = require('../utils/authHandler')
let jwt = require('jsonwebtoken')
let fs = require('fs')
let path = require('path')

const privateKey = fs.readFileSync(path.join(__dirname, '../private.pem'), 'utf8');

router.post('/register', RegisterValidator, validationResult, async function (req, res, next) {
    try {
        let newItem = await userController.CreateAnUser(
            req.body.username, req.body.password, req.body.email,
            "69af870aaa71c433fa8dda8e"
        )
        res.send(newItem);
    } catch (err) {
        res.status(400).send({ message: err.message });
    }
})

router.post('/login', async function (req, res, next) {
    try {
        let { username, password } = req.body;
        let result = await userController.FindUserByUsername(username);
        if (!result) {
            res.status(403).send("sai thong tin dang nhap");
            return;
        }
        if (result.lockTime > Date.now()) {
            res.status(404).send("ban dang bi ban");
            return;
        }
        result = await userController.CompareLogin(result, password);
        if (!result) {
            res.status(403).send("sai thong tin dang nhap");
            return;
        }
        
        let token = jwt.sign({
            id: result._id
        }, privateKey, {
            expiresIn: '1d',
            algorithm: 'RS256'
        })
        
        res.cookie("LOGIN_NNPTUD_S3", token, {
            maxAge: 24 * 60 * 60 * 1000,
            httpOnly: true
        })
        res.send(token)

    } catch (err) {
        res.status(400).send({ message: err.message });
    }
})

router.get('/me', CheckLogin, function (req, res, next) {
    let user = req.user;
    res.send(user)
})

router.post('/logout', CheckLogin, function (req, res, next) {
    res.cookie("LOGIN_NNPTUD_S3", "", {
        maxAge: 0,
        httpOnly: true
    })
    res.send("da logout ")
})

router.post('/changepassword', CheckLogin, async function (req, res, next) {
    try {
        let { oldpassword, newpassword } = req.body;

        if (!newpassword || newpassword.length < 6) {
            return res.status(400).send({ message: "Mật khẩu mới phải có ít nhất 6 ký tự" });
        }
        if (!oldpassword) {
            return res.status(400).send({ message: "Vui lòng nhập mật khẩu cũ" });
        }

        let result = await userController.ChangePassword(req.user._id, oldpassword, newpassword);
        
        if (!result.success) {
            return res.status(400).send({ message: result.message });
        }
        
        res.send({ message: result.message });

    } catch (err) {
        res.status(500).send({ message: err.message });
    }
})

module.exports = router;