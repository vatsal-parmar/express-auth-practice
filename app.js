require('./config/database').connect();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const User = require('./model/user');
const auth = require('./middleware/auth');

const app = express();

app.use(express.json());
app.use(cookieParser());

app.get('/', (req, res) => {
  res.send('<h1>Hello from auth system</h1>');
});

app.post('/register', async (req, res) => {
  try {
    const { firstname, lastname, email, password } = req.body;

    if (!(email && password && firstname && lastname)) {
      res.status(400).json('All fields required');
    }

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      res.status(401).json('User already exists');
    }

    const encryptedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      firstname,
      lastname,
      email: email.toLowerCase(),
      password: encryptedPassword,
    });

    const token = jwt.sign(
      {
        user_id: user._id,
        email,
      },
      process.env.SECRET_KEY,
      {
        expiresIn: '2h',
      }
    );
    user.token = token;
    // update or not in db

    user.password = undefined;

    res.status(201).json(user);
  } catch (error) {
    console.log(error);
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!(email && password)) {
      res.status(400).send('Field is missing');
    }

    const user = await User.findOne({ email });

    if (user && (await bcrypt.compare(password, user.password))) {
      const token = jwt.sign(
        { user_id: user._id, email },
        process.env.SECRET_KEY,
        { expiresIn: '2h' }
      );

      user.token = token;
      user.password = undefined;
      // res.status(200).json(user);

      // if we want to use cookies

      const options = {
        expires: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
        httpOnly: true,
      };

      res
        .status(200)
        .cookie('token', token, options)
        .json({ success: true, token });
    } else {
      res.status(400).send('invalid email or password');
    }
  } catch (error) {
    console.log(error);
  }
});

app.get('/dashboard', auth, (req, res) => {
  res.send('Welcome to dashboard');
});

module.exports = app;
