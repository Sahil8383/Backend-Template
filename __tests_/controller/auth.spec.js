const bcrypt = require('bcrypt'); 
const jwt = require('jsonwebtoken');
const { LoginIn, SignUp } = require('../../controllers/UserController');
const User = require('../../models/User'); 

jest.mock('../../models/User'); 
jest.mock('bcrypt'); 
jest.mock('jsonwebtoken'); 

const req = {
    body: {
        email: 'test@example.com',
        password: '1234'
    }
};

const res = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn(),
    setHeader: jest.fn()
};

describe('LoginIn function', () => {
    afterEach(() => {
        jest.clearAllMocks();
    });

    it('should return 400 if user is not found', async () => {
        // Mock User.findOne to return null (user not found)
        User.findOne.mockResolvedValue(null);

        await LoginIn(req, res);

        expect(res.status).toHaveBeenCalledWith(400);
        expect(res.json).toHaveBeenCalledWith({ msg: "Invalid credentials" });
    });

    it('should return 400 if password does not match', async () => {
        const mockUser = {
            email: 'test@example.com',
            password: 'hashed_password'
        };

        // Mock User.findOne to return a user
        User.findOne.mockResolvedValue(mockUser);

        // Mock bcrypt.compare to return false (password mismatch)
        bcrypt.compare.mockResolvedValue(false);

        await LoginIn(req, res);

        expect(res.status).toHaveBeenCalledWith(400);
        expect(res.json).toHaveBeenCalledWith({ msg: "Invalid credentials" });
    });

    it('should return 200 and a token if login is successful', async () => {
        const mockUser = {
            _id: 'user_id',
            email: 'test@example.com',
            password: 'hashed_password'
        };

        // Mock User.findOne to return a user
        User.findOne.mockResolvedValue(mockUser);

        // Mock bcrypt.compare to return true (password matches)
        bcrypt.compare.mockResolvedValue(true);

        // Mock jwt.sign to return a mock token
        const mockToken = 'mock_jwt_token';
        jwt.sign.mockReturnValue(mockToken);

        await LoginIn(req, res);

        expect(bcrypt.compare).toHaveBeenCalledWith('1234', 'hashed_password');
        expect(jwt.sign).toHaveBeenCalledWith({ id: 'user_id' }, process.env.ACCESS_KEY);

        expect(res.setHeader).toHaveBeenCalledWith('authorization', mockToken);
        expect(res.setHeader).toHaveBeenCalledWith('userid', 'user_id');
        expect(res.status).toHaveBeenCalledWith(200);
        expect(res.json).toHaveBeenCalledWith({
            token: mockToken,
            user: mockUser,
            userId: mockUser._id
        });
    });

    it('should handle server errors and return 500', async () => {
        // Mock an error in User.findOne
        User.findOne.mockRejectedValue(new Error('Server error'));

        await LoginIn(req, res);

        expect(res.status).toHaveBeenCalledWith(500);
        expect(res.json).toHaveBeenCalledWith({ error: 'Server error' });
    });
});

const reqSignup = {
    body: {
        name:'Sahil',
        email: 'test@example.com',
        password: '1234'
    }
}

const resSignup = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn()
}

describe('Sign Up user', () => {
    afterEach(() => {
        jest.clearAllMocks();
    });

    it('it should return 200 when user created', async () => {
        const mockUser = {
            name:'Sahil',
            email: 'test@example.com',
            password: '1234'
        }

        bcrypt.genSalt = jest.fn().mockResolvedValue('mock_salt');
        bcrypt.hash = jest.fn().mockResolvedValue('hashed_password');

        User.prototype.save = jest.fn().mockResolvedValue(mockUser);

        await SignUp(reqSignup,resSignup);

        expect(bcrypt.genSalt).toHaveBeenCalledWith();  // Check that genSalt is called
        expect(bcrypt.hash).toHaveBeenCalledWith('1234', 'mock_salt');  // Ensure bcrypt hashes password correctly

        expect(resSignup.status).toHaveBeenCalledWith(201);  // Check if status 201 is set
        expect(resSignup.json).toHaveBeenCalledWith(mockUser);
    })

    it('server error', async () => {
        User.prototype.save = jest.fn().mockRejectedValue(new Error('Server error'));

        await SignUp(reqSignup,resSignup);

        expect(resSignup.status).toHaveBeenCalledWith(500);
        expect(resSignup.json).toHaveBeenCalledWith({error:'Server error'})
    })
})