const User = require('../models/User');
const jwt = require('jsonwebtoken');
const bycrypt = require('bcrypt');

const authMiddleware = (req, res, next) => {

    const token = req.header('authorization');

    if (!token) {
        return res.status(401).json({ msg: 'Authorization denied, no token provided' });
    }

    try {

        const decoded = jwt.verify(token, process.env.ACCESS_KEY);


        req.user = decoded;
        next(); 
    } catch (error) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
};


const SignUp = async (req, res) => {
    try {
        const { name, email, password, } = req.body;

        const salt = await bycrypt.genSalt();
        const passwordHash = await bycrypt.hash(password, salt);

        const newUser = new User({
            name,
            email,
            password: passwordHash,
        });

        const user = await newUser.save();
        res.status(201);
        res.json(user);
    } catch (error) {
        res.status(500);
        res.json({ error: error.message });
    }
}

const LoginIn = async (req, res) => {
    try {

        const { email, password } = req.body;

        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ msg: "Invalid credentials" });
        }

        const isMatch = await bycrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).json({ msg: "Invalid credentials" });
        }

        const token = jwt.sign({ id: user._id }, process.env.ACCESS_KEY);
        delete user.password;
        res.setHeader('authorization', token);
        res.setHeader('userid', user._id);
        res.status(200).json({ token, user ,  userId: user._id });

    } catch (error) {

        res.status(500).json({ error: error.message });

    }
}


module.exports = {
    SignUp,
    LoginIn,
    authMiddleware
}