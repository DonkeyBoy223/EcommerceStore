const express = require('express');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const dotenv = require('dotenv').config()
const DiscordStrategy = require('passport-discord').Strategy;
const crypto = require('crypto');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');
const nodemailer = require('nodemailer');
const argon2 = require('argon2');
const mysql = require('mysql2');
const app = express();
const port = 5000;

app.use(cors());
app.use(bodyParser.json()); // To parse JSON data
app.use(bodyParser.urlencoded({ extended: true }));

const databaseUser = process.env.DATABASE_USER;
const databasePass = process.env.DATABASE_PASS;
const databaseHost = process.env.DATABASE_HOST;
const secretKey = process.env.SECRET_KEY;

// Create a MySQL connection pool
const pool = mysql.createPool({
  host: databaseHost,
  user: databaseUser,
  password: databasePass,
  database: 'mystore',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

const generateJwtToken = (payload, secretKey, expiresIn) => {
    return jwt.sign(payload, secretKey, { expiresIn });
};
app.post('/register', async (req, res) => {
    const { username, password, email, firstname, lastname } = req.body;
  
    try {
      // Check if the username or email already exists in the database
      const usernameExists = await getUserByUsername(username);
      const emailExists = await getUserByEmail(email);
  
      if (usernameExists) {
        return res.status(400).json({ error: 'Username already exists' });
      }
  
      if (emailExists) {
        return res.status(400).json({ error: 'Email already exists' });
      }
  
      // Hash the password using Argon2 (or any other hashing algorithm)
      const hashedPassword = await argon2.hash(password);
  
      // Create a new user object with the provided data
      const newUser = {
        username: username,
        password: hashedPassword,
        email: email,
        firstname: firstname,
        lastname: lastname,
      };
  
      // Insert the new user into the database using parameterized query
      const query = 'INSERT INTO allusers (username, password, email, firstname, lastname) VALUES (?, ?, ?, ?, ?)';
      const values = [newUser.username, newUser.password, newUser.email, newUser.firstname, newUser.lastname];
  
      pool.query(query, values, (err, result) => {
        if (err) {
          console.error('Error adding user to database:', err);
          res.status(500).json({ error: 'Internal server error' });
        } else {
          console.log('New user added:', result.insertId);
          res.json({ message: 'User registration successful' });
        }
      });
    } catch (error) {
      console.error('Error hashing password:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });
  
  
  async function getUserByUsername(username) {
    try {
      const [results] = await pool.promise().query('SELECT * FROM allusers WHERE username = ?', [username]);
      if (results.length === 0) {
        return null; // User not found
      } else {
        console.log('User Found', results[0])
        return results[0]; // Return the first (and only) user found
      }
    } catch (error) {
      console.error('Error fetching user by username:', error);
      throw error;
    }
  }
  async function getUserByEmailLogin(email) {
    try {
      const [results] = await pool.promise().query('SELECT * FROM allusers WHERE email = ?', [email]);
      if (results.length === 0) {
        return null; // User not found
      } else {
        console.log('User Found', results[0])
        return results[0]; // Return the first (and only) user found
      }
    } catch (error) {
      console.error('Error fetching user by email:', error);
      throw error;
    }
  }
  
  async function getUserByEmail(email) {
    return new Promise((resolve, reject) => {
      pool.query('SELECT * FROM allusers WHERE email = ?', [email], (err, results) => {
        if (err) {
          reject(err);
        } else if (results.length === 0) {
          resolve(null); // User not found
        } else {
          resolve(results[0]); // Return the first (and only) user found
        }
      });
    });
  }
  async function generateRefreshToken(email) {
    try {
      // Check if the user already has a valid refresh token in the database
      const [results] = await pool.promise().query(
        'SELECT refresh_token FROM refreshtokens WHERE email = ? AND expiration_date > NOW()',
        [email]
      );
  
      if (results.length > 0) {
        // If a valid refresh token exists, return it
        console.log(`Refresh token still valid for ${email}`)
        return results[0].refresh_token;
      } else {
        // If no valid refresh token exists, generate a new one
        const refreshToken = Math.random().toString(36).substring(2);
        const expirationDate = new Date(Date.now() + (30 * 24 * 60 * 60 * 1000)); // Set expiration to 30 days from now
  
        // Insert the refresh token and its expiration date into the refresh_tokens table
        await pool.promise().query(
          'INSERT INTO refreshtokens (refresh_token, email, expiration_date) VALUES (?, ?, ?)',
          [refreshToken, email, expirationDate]
        );
  
        return refreshToken;
      }
    } catch (error) {
      console.error('Error storing/generating refresh token in the database:', error);
      throw error;
    }
  }
  
  
  
  app.post('/login', async (req, res) => {
    const { email, password } = req.body;
  
    try {
      // Fetch the user from the database based on the provided username
      const user = await getUserByEmailLogin(email);
  
      // If the user is not found in the database, return an error response
      if (!user) {
        console.log('User not found:', email);
        return res.status(401).json({ error: 'Invalid credentials' });
      }
  
      // Compare the provided password with the hashed password from the database using Argon2
      const passwordValid = await argon2.verify(user.password, password);
  
      if (passwordValid) {
        // Password is correct, allow the user to log in
        const accessToken = generateJwtToken({ userId: user.id }, secretKey, '30m');
        const refreshToken = await generateRefreshToken(user.email);
        res.cookie('refreshToken', refreshToken, {
            maxAge: 5 * 60 * 60 * 1000, // 5 hours in milliseconds
            httpOnly: true, // The cookie can only be accessed by the server, not by JavaScript in the browser
          }); // Pass the user's id to generateRefreshToken
        res.json({ accessToken });
      } else {
        console.log('Invalid password for user:', email);
        // Password is incorrect
        res.status(401).json({ error: 'Invalid credentials, please check your email or password!' });
      }
    } catch (error) {
      console.error('Error during login:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });
  app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
  
    try {
      // Check if the email exists in the user table
      const [results] = await pool.promise().query('SELECT * FROM allusers WHERE email = ?', [email]);
      if (results.length === 0) {
        // Email not found in the user table, return an error response
        console.log('Email not found:', email);
        return res.status(404).json({ error: 'Email not found' });
      }
  
      // Generate a unique password reset token
      const resetToken = crypto.randomBytes(20).toString('hex');
  
      // Store the password reset token and expiration timestamp in the user table
      const expirationDate = new Date(Date.now() + 3600000 ); // Token will expire in 30 seconds \// Token will expire in 1 hour
      await pool.promise().query('UPDATE user SET reset_token = ?, reset_token_expiration = ? WHERE email = ?', [resetToken, expirationDate, email]);
  
      const transporter = nodemailer.createTransport({
        service: 'gmail', // Replace with your email service provider
        auth: {
          user: 'sdoncaster5@gmail.com', // Replace with your email address
          pass: 'qzvvpmnkpoodfxlw', // Replace with your email password
        },
      });
    
      const mailOptions = {
        from: 'sdoncaster5@gmail.com',
        to: email,
        subject: 'Password Reset Request',
        html: `<p>Click the following link to reset your password: <a href="http://localhost:3000/reset-password?token=${resetToken}">Reset Password</a></p>`
      };
    
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error('Error sending email:', error);
          res.status(500).json({ error: 'Failed to send password reset email' });
        } else {
          console.log('Email sent:', info.response);
          res.json({ message: 'Password reset email sent successfully' });
        }
      });
  
      console.log('Password reset token:', resetToken);
      res.json({ message: 'Password reset email sent successfully' });
    } catch (error) {
      console.error('Error during password reset:', error);
      res.status(500).json({ error: 'Failed to initiate password reset' });
    }
  });
  // Assuming you have the required imports and setup for the backend

  app.post('/reset-password', async (req, res) => {
    const { token, password } = req.body;
  
    try {
      // Check if the token exists in the user table and if it's not expired
      const [results] = await pool.promise().query('SELECT * FROM allusers WHERE reset_token = ? AND reset_token_expiration > NOW()', [token]);
  
      if (results.length === 0) {
        // Token not found or expired, return an error response
        console.log('Invalid or expired token:', token);
        return res.status(400).json({ error: 'Invalid or expired token' });
      }
  
      // Generate a new password hash using Argon2
      const hashedPassword = await argon2.hash(password);
  
      // Update the user's password and remove the reset token from the database based on their email
      await pool.promise().query('UPDATE allusers SET password = ?, reset_token = NULL, reset_token_expiration = NULL WHERE email = ?', [hashedPassword, results[0].email]);
  
      console.log('Password reset successful for user:', results[0].email);
      res.json({ message: 'Password reset successful' });
    } catch (error) {
      console.error('Error resetting password:', error);
      res.status(500).json({ error: 'Failed to reset password' });
    }
  });

  // Define the /products route
  app.get('/api/products.json', async (req, res) => {
    try {
      const query = 'SELECT * FROM products'; // Change the query to get 5 random products
      const [results] = await pool.promise().query(query);
  
      // Send the product data back as an object
      res.json({ products: results });
    } catch (error) {
      console.error('Error fetching products:', error);
      res.status(500).json({ error: 'Failed to fetch products' });
    }
  });

  
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});