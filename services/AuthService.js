const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Joi = require('joi');

class AuthService {
  constructor() {
    // JWT Secret from environment variables (fallback for development only)
    this.jwtSecret = process.env.JWT_SECRET || 'dev-fallback-secret-change-in-production';
    this.saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12;
  }

  /**
   * Hash a password using bcrypt
   * @param {string} password - Plain text password
   * @returns {Promise<string>} - Hashed password
   */
  async hashPassword(password) {
    try {
      return await bcrypt.hash(password, this.saltRounds);
    } catch (error) {
      throw new Error('Failed to hash password');
    }
  }

  /**
   * Compare a plain text password with a hashed password
   * @param {string} plainPassword - Plain text password
   * @param {string} hashedPassword - Hashed password from database
   * @returns {Promise<boolean>} - True if passwords match
   */
  async comparePassword(plainPassword, hashedPassword) {
    try {
      return await bcrypt.compare(plainPassword, hashedPassword);
    } catch (error) {
      throw new Error('Failed to compare passwords');
    }
  }

  /**
   * Generate a JWT token for a user
   * @param {Object} payload - User data to include in token
   * @param {number} payload.userId - User ID
   * @param {string} payload.username - Username
   * @param {string} payload.email - User email
   * @param {string} [expiresIn='24h'] - Token expiration time
   * @returns {string} - JWT token
   */
  generateToken(payload, expiresIn = '24h') {
    try {
      const { userId, username, email } = payload;
      return jwt.sign(
        { userId, username, email },
        this.jwtSecret,
        { expiresIn }
      );
    } catch (error) {
      throw new Error('Failed to generate JWT token');
    }
  }

  /**
   * Verify and decode a JWT token
   * @param {string} token - JWT token to verify
   * @returns {Object} - Decoded token payload
   * @throws {Error} - If token is invalid or expired
   */
  verifyToken(token) {
    try {
      return jwt.verify(token, this.jwtSecret);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new Error('Token has expired');
      } else if (error.name === 'JsonWebTokenError') {
        throw new Error('Invalid token');
      } else {
        throw new Error('Token verification failed');
      }
    }
  }

  /**
   * Extract token from Authorization header
   * @param {string} authHeader - Authorization header value
   * @returns {string|null} - Extracted token or null if not found
   */
  extractTokenFromHeader(authHeader) {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }
    return authHeader.replace('Bearer ', '');
  }

  /**
   * Validate user registration data
   * @param {Object} userData - User registration data
   * @returns {Object} - Validation result with error and value properties
   */
  validateRegistrationData(userData) {
    const schema = Joi.object({
      username: Joi.string().min(3).max(50).required(),
      email: Joi.string().email().required(),
      password: Joi.string().min(6).required(),
      first_name: Joi.string().max(50).required(),
      last_name: Joi.string().max(50).required(),
      phone: Joi.string().max(20),
      address: Joi.string().max(500)
    });

    return schema.validate(userData);
  }

  /**
   * Validate user login data
   * @param {Object} loginData - User login data
   * @returns {Object} - Validation result with error and value properties
   */
  validateLoginData(loginData) {
    const schema = Joi.object({
      username: Joi.string().required(),
      password: Joi.string().required()
    });

    return schema.validate(loginData);
  }

  /**
   * Authenticate a user by verifying their credentials
   * @param {string} plainPassword - Plain text password provided by user
   * @param {string} hashedPassword - Hashed password from database
   * @returns {Promise<boolean>} - True if authentication succeeds
   */
  async authenticateUser(plainPassword, hashedPassword) {
    return await this.comparePassword(plainPassword, hashedPassword);
  }

  /**
   * Create a user payload for JWT token from user database record
   * @param {Object} user - User record from database
   * @returns {Object} - User payload for JWT
   */
  createUserPayload(user) {
    return {
      userId: user.id,
      username: user.username,
      email: user.email
    };
  }

  /**
   * Create a sanitized user object for API responses (removes sensitive data)
   * @param {Object} user - User record from database
   * @returns {Object} - Sanitized user object
   */
  createUserResponse(user) {
    return {
      id: user.id,
      username: user.username,
      email: user.email,
      first_name: user.first_name,
      last_name: user.last_name
    };
  }
}

module.exports = new AuthService();
