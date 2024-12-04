import express from 'express'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcryptjs'
import dotenv from 'dotenv'
import bodyParser from 'body-parser'
import morgan from 'morgan'

import { db } from './src/config/db.js'

dotenv.config();

const PORT = process.env.PORT;
const SALT = process.env.SALT;
const app = express();

// middlewares
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.json());
app.use(cors());
app.use(morgan(':method :url :status :res[content-length] - :response-time ms'));

// MySQL connection setup


db.connect((err) => {
    if(err){
        console.log('Error connecting to the database: ', err);
        return;
    }else{
        console.log('Connected to the MySQL database.');
    }
})

// register

app.post('/register', (req, res) => {
    const {username, password} = req.body;
    
    bcrypt.hash(password, SALT, (err, hashedPassword) => {
        if(err){
            return res.status(500).json({message: 'Error hashing password.'});
        }

        const query = 'INSERT INTO users (username, password) VALUES (?, ?)';
        db.query(query, [username, hashedPassword], (err, result) => {
            if(err){
                return res.status(500).json({message: 'Error saving user.'});
            }
            res.status(201).json({message: 'Registration successful!'});
        });
    });
});

// login

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const query = 'SELECT * FROM users WHERE username = ?';
    db.query(query, [username], (err, results) => {
        if (err || results.length === 0) {
            return res.status(400).json({ message: 'User not found!' });
        }

        const user = results[0];

        bcrypt.compare(password, user.password, (err, isMatching) => {
            if (err || !isMatching) {
                return res.status(400).json({ message: 'Incorrect password!' });
            }

            // Generate access token
            const accessToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '15m' });

            // Generate refresh token
            const refreshToken = jwt.sign({ userId: user.id }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });

            // Save refresh token in the database
            const insertQuery = 'INSERT INTO refresh_tokens (user_id, token) VALUES (?, ?)';
            db.query(insertQuery, [user.id, refreshToken], (err) => {
                if (err) {
                    return res.status(500).json({ message: 'Error saving refresh token.' });
                }
                res.json({ accessToken, refreshToken });
            });
        });
    });
});

// refresh token

app.post('/refresh-token', (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(401).json({ message: 'Refresh token is required' });
    }

    // Verify the refresh token
    jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid refresh token' });
        }

        const query = 'SELECT * FROM refresh_tokens WHERE token = ?';
        db.query(query, [refreshToken], (err, results) => {
            if (err || results.length === 0) {
                return res.status(403).json({ message: 'Refresh token not found or revoked' });
            }

            const userId = decoded.userId;

            // Generate a new access token
            const accessToken = jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '15m' });

            res.json({ accessToken });
        });
    });
});

// logout

app.post('/logout', (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(400).json({ message: 'Refresh token is required' });
    }

    const query = 'DELETE FROM refresh_tokens WHERE token = ?';
    db.query(query, [refreshToken], (err) => {
        if (err) {
            return res.status(500).json({ message: 'Error revoking refresh token' });
        }

        res.status(200).json({ message: 'Logged out successfully' });
    });
});


// protected route

app.get('/profile', (req, res) => {
    const token = req.headers['authorization'];

    if(!token){
        return res.status(401).json({message: 'No token provided'});
    }

    // verify token
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if(err){
            return res.status(401).json({message: 'Invalid token'});
        }

        // Fetch user profile
        const query = 'SELECT * FROM users WHERE username = ?';
        db.query(query, [decoded.userId], (err, results) => {
            if(err || results.length === 0){
                return res.status(404).json({message: 'User not found'});
            }

            const user = results[0];
            res.json({username: user.username});
        });
    });
});

app.get('/', (req, res) => {
    res.status(200).json({status: 200, message: 'Server is up and running!'});
});

app.listen(PORT, () => {
    console.log(`API is running on http://localhost:${PORT}`);
});