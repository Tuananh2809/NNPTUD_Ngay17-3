let userController = require('../controllers/users')
let jwt = require('jsonwebtoken')
let fs = require('fs')
let path = require('path') // Cần thêm path để trỏ đường dẫn chính xác

// Đọc file public.pem từ thư mục gốc
const publicKey = fs.readFileSync(path.join(__dirname, '../public.pem'), 'utf8');

module.exports = {
    CheckLogin: async function (req, res, next) {
        let key = req.headers.authorization;
        
        // Hỗ trợ xử lý token từ Postman (Tab Authorization tự thêm chữ "Bearer ")
        if (key && key.toLowerCase().startsWith('bearer ')) {
            key = key.split(' ')[1];
        }

        if (!key) {
            if (req.cookies.LOGIN_NNPTUD_S3) {
                key = req.cookies.LOGIN_NNPTUD_S3;
            } else {
                res.status(404).send("ban chua dang nhap")
                return;
            }
        }

        try {
            // Sửa lại jwt.verify: dùng publicKey và thuật toán RS256
            let result = jwt.verify(key, publicKey, { algorithms: ['RS256'] })
            
            if (result.exp * 1000 < Date.now()) {
                res.status(404).send("ban chua dang nhap")
                return; // Đã sửa lỗi gõ nhầm 'return;s' ở code cũ của bạn
            }
            
            let user = await userController.GetUserById(result.id);
            if (!user) {
                res.status(404).send("ban chua dang nhap")
                return;
            }
            
            req.user = user;
            next();
        } catch (error) {
            // Nên in log lỗi ra để dễ debug nếu token có vấn đề
            console.log("JWT Verify Error: ", error.message);
            res.status(404).send("ban chua dang nhap")
            return;
        }
    }
}