const bcrypt = require('bcryptjs');
const { generateToken, authorize } = require('./helpers');
const users = [];

exports.hello = async (event) => {
  const auth = authorize(event);
  if (!auth.isValid) {
    return {
      statusCode: 401,
      body: JSON.stringify({ error: auth.error }),
    };
  }
  return {
    statusCode: 200,
    body: JSON.stringify({
      message: "Go Serverless v4! Your function executed successfully!",
    }),
  };
};

exports.register = async (event) => {
  try {
    const { email, password } = JSON.parse(event.body);

    if (!email || !password) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'Email and password are required' }),
      };
    }

    // Check if user already exists
    const existingUser = users.find(user => user.email === email);
    if (existingUser) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'User already exists' }),
      };
    }

    const hashedPassword = await bcrypt.hash(password, 10);


    const user = {
      id: users.length + 1,
      email,
      password: hashedPassword
    };
    users.push(user);

    const token = generateToken(user.id);

    return {
      statusCode: 201,
      body: JSON.stringify({
        message: 'User registered successfully',
        token,
        user: { id: user.id, email: user.email }
      }),
    };
  } catch (error) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal server error' }),
    };
  }
};


exports.login = async (event) => {
  try {
    const {email, password} = JSON.parse(event.body);

    if (!email || !password) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'Email and password are required' }),
      };
    }

    const user = users.find(user => user.email === email);
    if (!user) {
      return {
        statusCode: 401,
        body: JSON.stringify({ error: 'Invalid credentials' }),
      };
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return {
        statusCode: 401,
        body: JSON.stringify({ error: 'Invalid credentials' }),
      };
    }

    const token = generateToken(user.id);

    return {
      statusCode: 200,
      body: JSON.stringify({
        message: 'Login successful',
        token,
        user: { id: user.id, email: user.email }
      }),
    };
  } catch (error) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal server error' }),
    };
  }
};

