const jwt = require('jsonwebtoken');

const authorize = (event) => {
    const token = event.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      return { isValid: false, error: 'No token provided' };
    }
  
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      return { isValid: true, userId: decoded.userId };
    } catch (error) {
      return { isValid: false, error: 'Invalid token' };
    }
  };

const generateToken = (userId) => {
    return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '24h' });
  };

  module.exports = { authorize, generateToken };