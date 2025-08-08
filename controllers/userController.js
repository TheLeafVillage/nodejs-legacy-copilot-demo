const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const { db } = require('../config/database');

// This is a LARGE MONOLITHIC CONTROLLER that handles multiple responsibilities
// This is intentionally poorly designed for the workshop - DO NOT use this pattern in production!

class UserController {
  constructor() {
    // JWT Secret from environment variables (fallback for development only)
    this.jwtSecret = process.env.JWT_SECRET || 'dev-fallback-secret-change-in-production';
    this.saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12;
  }

  // Mock email service - simulates sending emails without external dependencies
  async sendEmail(to, subject, html, emailType = 'general') {
    // Simulate email sending by logging the email details
    console.log(`📧 [MOCK EMAIL] To: ${to}, Subject: ${subject}`);
    console.log(`📧 [MOCK EMAIL] Type: ${emailType}`);
    console.log(`📧 [MOCK EMAIL] Content: ${html.substring(0, 100)}...`);
    
    // Simulate a small delay as real email services would have
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Return success (in a real scenario, this could occasionally fail)
    return { success: true, messageId: 'mock_' + Date.now() };
  }

  // Mock payment processing - simulates payment without external services
  async processPayment(amount, paymentMethod, paymentToken) {
    console.log(`💳 [MOCK PAYMENT] Processing $${amount} via ${paymentMethod}`);
    console.log(`💳 [MOCK PAYMENT] Token: ${paymentToken}`);
    
    // Simulate payment processing delay
    await new Promise(resolve => setTimeout(resolve, 200));
    
    // Simulate success/failure (90% success rate for demonstration)
    const success = Math.random() > 0.1;
    
    if (success) {
      const transactionId = `${paymentMethod}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      console.log(`💳 [MOCK PAYMENT] Success - Transaction ID: ${transactionId}`);
      return { success: true, transactionId };
    } else {
      console.log(`💳 [MOCK PAYMENT] Failed - Simulated payment failure`);
      return { success: false, error: 'Payment failed - insufficient funds or invalid payment method' };
    }
  }

  // MASSIVE METHOD THAT HANDLES USER REGISTRATION
  async register(req, res) {
    try {
      // Input validation
      const schema = Joi.object({
        username: Joi.string().min(3).max(50).required(),
        email: Joi.string().email().required(),
        password: Joi.string().min(6).required(),
        first_name: Joi.string().max(50).required(),
        last_name: Joi.string().max(50).required(),
        phone: Joi.string().max(20),
        address: Joi.string().max(500)
      });

      const { error, value } = schema.validate(req.body);
      if (error) {
        return res.status(400).json({ error: error.details[0].message });
      }

      const { username, email, password, first_name, last_name, phone, address } = value;

      // Check if user already exists
      const existingUser = await new Promise((resolve, reject) => {
        db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, email], (err, row) => {
          if (err) reject(err);
          else resolve(row);
        });
      });

      if (existingUser) {
        return res.status(409).json({ error: 'User already exists with this username or email' });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, this.saltRounds);

      // Insert user into database
      const userId = await new Promise((resolve, reject) => {
        db.run(
          'INSERT INTO users (username, email, password, first_name, last_name, phone, address) VALUES (?, ?, ?, ?, ?, ?, ?)',
          [username, email, hashedPassword, first_name, last_name, phone, address],
          function(err) {
            if (err) reject(err);
            else resolve(this.lastID);
          }
        );
      });

      // Generate JWT token
      const token = jwt.sign(
        { userId, username, email },
        this.jwtSecret,
        { expiresIn: '24h' }
      );

      // Log analytics event for user registration
      await new Promise((resolve, reject) => {
        db.run(
          'INSERT INTO analytics_events (user_id, event_type, event_data, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)',
          [userId, 'user_registration', JSON.stringify({ username, email }), req.ip, req.get('User-Agent')],
          (err) => {
            if (err) reject(err);
            else resolve();
          }
        );
      });

      // Send welcome email
      const emailSubject = 'Welcome to Our Platform!';
      const emailHtml = `
        <h1>Welcome ${first_name}!</h1>
        <p>Thank you for registering with our platform. We're excited to have you on board!</p>
        <p>Your username is: ${username}</p>
        <p>You can now start exploring our features.</p>
        <br>
        <p>Best regards,</p>
        <p>The Team</p>
      `;

      try {
        const emailResult = await this.sendEmail(email, emailSubject, emailHtml, 'welcome');

        // Log email send
        await new Promise((resolve, reject) => {
          db.run(
            'INSERT INTO email_logs (user_id, email_type, recipient, subject, status) VALUES (?, ?, ?, ?, ?)',
            [userId, 'welcome', email, emailSubject, 'sent'],
            (err) => {
              if (err) reject(err);
              else resolve();
            }
          );
        });
      } catch (emailError) {
        console.error('Failed to send welcome email:', emailError);
        // Log email failure
        await new Promise((resolve, reject) => {
          db.run(
            'INSERT INTO email_logs (user_id, email_type, recipient, subject, status) VALUES (?, ?, ?, ?, ?)',
            [userId, 'welcome', email, emailSubject, 'failed'],
            (err) => {
              if (err) reject(err);
              else resolve();
            }
          );
        });
      }

      res.status(201).json({
        message: 'User registered successfully',
        user: {
          id: userId,
          username,
          email,
          first_name,
          last_name
        },
        token
      });

    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({ error: 'Internal server error during registration' });
    }
  }

  // MASSIVE METHOD THAT HANDLES USER LOGIN AND ANALYTICS
  async login(req, res) {
    try {
      // Input validation
      const schema = Joi.object({
        username: Joi.string().required(),
        password: Joi.string().required()
      });

      const { error, value } = schema.validate(req.body);
      if (error) {
        return res.status(400).json({ error: error.details[0].message });
      }

      const { username, password } = value;

      // Find user by username or email
      const user = await new Promise((resolve, reject) => {
        db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, username], (err, row) => {
          if (err) reject(err);
          else resolve(row);
        });
      });

      if (!user) {
        // Log failed login attempt
        await new Promise((resolve, reject) => {
          db.run(
            'INSERT INTO analytics_events (event_type, event_data, ip_address, user_agent) VALUES (?, ?, ?, ?)',
            ['failed_login_attempt', JSON.stringify({ attempted_username: username }), req.ip, req.get('User-Agent')],
            (err) => {
              if (err) reject(err);
              else resolve();
            }
          );
        });
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Verify password
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        // Log failed login attempt with valid username
        await new Promise((resolve, reject) => {
          db.run(
            'INSERT INTO analytics_events (user_id, event_type, event_data, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)',
            [user.id, 'failed_login_invalid_password', JSON.stringify({ username: user.username }), req.ip, req.get('User-Agent')],
            (err) => {
              if (err) reject(err);
              else resolve();
            }
          );
        });
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Generate JWT token
      const token = jwt.sign(
        { userId: user.id, username: user.username, email: user.email },
        this.jwtSecret,
        { expiresIn: '24h' }
      );

      // Log successful login
      await new Promise((resolve, reject) => {
        db.run(
          'INSERT INTO analytics_events (user_id, event_type, event_data, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)',
          [user.id, 'successful_login', JSON.stringify({ username: user.username }), req.ip, req.get('User-Agent')],
          (err) => {
            if (err) reject(err);
            else resolve();
          }
        );
      });

      res.json({
        message: 'Login successful',
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          first_name: user.first_name,
          last_name: user.last_name
        },
        token
      });

    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ error: 'Internal server error during login' });
    }
  }

  // MASSIVE METHOD THAT HANDLES ORDER CREATION, PAYMENT, AND NOTIFICATIONS
  async createOrder(req, res) {
    try {
      // Extract user from JWT token
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) {
        return res.status(401).json({ error: 'No token provided' });
      }

      let decoded;
      try {
        decoded = jwt.verify(token, this.jwtSecret);
      } catch (jwtError) {
        return res.status(401).json({ error: 'Invalid token' });
      }

      // Input validation
      const schema = Joi.object({
        items: Joi.array().items(
          Joi.object({
            product_name: Joi.string().required(),
            quantity: Joi.number().integer().min(1).required(),
            price: Joi.number().min(0).required()
          })
        ).min(1).required(),
        shipping_address: Joi.string().required(),
        payment_method: Joi.string().valid('stripe', 'paypal', 'bank_transfer').required(),
        payment_token: Joi.string().required()
      });

      const { error, value } = schema.validate(req.body);
      if (error) {
        return res.status(400).json({ error: error.details[0].message });
      }

      const { items, shipping_address, payment_method, payment_token } = value;

      // Calculate total amount
      const totalAmount = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);

      // Create order in database
      const orderId = await new Promise((resolve, reject) => {
        db.run(
          'INSERT INTO orders (user_id, total_amount, shipping_address, payment_method) VALUES (?, ?, ?, ?)',
          [decoded.userId, totalAmount, shipping_address, payment_method],
          function(err) {
            if (err) reject(err);
            else resolve(this.lastID);
          }
        );
      });

      // Insert order items
      for (const item of items) {
        await new Promise((resolve, reject) => {
          db.run(
            'INSERT INTO order_items (order_id, product_name, quantity, price) VALUES (?, ?, ?, ?)',
            [orderId, item.product_name, item.quantity, item.price],
            (err) => {
              if (err) reject(err);
              else resolve();
            }
          );
        });
      }

      // Process payment based on payment method
      let paymentResult = { success: false, transactionId: null };

      // Use our mock payment service instead of external payment processors
      paymentResult = await this.processPayment(totalAmount, payment_method, payment_token);

      // Update order with payment status
      const paymentStatus = paymentResult.success ? 'completed' : 'failed';
      const orderStatus = paymentResult.success ? 'confirmed' : 'payment_failed';

      await new Promise((resolve, reject) => {
        db.run(
          'UPDATE orders SET payment_status = ?, status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
          [paymentStatus, orderStatus, orderId],
          (err) => {
            if (err) reject(err);
            else resolve();
          }
        );
      });

      // Get user details for email
      const user = await new Promise((resolve, reject) => {
        db.get('SELECT * FROM users WHERE id = ?', [decoded.userId], (err, row) => {
          if (err) reject(err);
          else resolve(row);
        });
      });

      // Send order confirmation email
      if (paymentResult.success) {
        const emailSubject = `Order Confirmation - #${orderId}`;
        const itemsList = items.map(item => `${item.quantity}x ${item.product_name} - $${item.price.toFixed(2)}`).join('<br>');
        
        const emailHtml = `
          <h1>Order Confirmed!</h1>
          <p>Dear ${user.first_name},</p>
          <p>Your order #${orderId} has been confirmed and payment has been processed successfully.</p>
          
          <h3>Order Details:</h3>
          <p><strong>Items:</strong><br>${itemsList}</p>
          <p><strong>Total Amount:</strong> $${totalAmount.toFixed(2)}</p>
          <p><strong>Shipping Address:</strong> ${shipping_address}</p>
          <p><strong>Payment Method:</strong> ${payment_method}</p>
          <p><strong>Transaction ID:</strong> ${paymentResult.transactionId}</p>
          
          <p>We'll send you tracking information once your order ships.</p>
          
          <p>Thank you for your business!</p>
          <p>The Team</p>
        `;

        try {
          await this.sendEmail(user.email, emailSubject, emailHtml, 'order_confirmation');

          // Log email send
          await new Promise((resolve, reject) => {
            db.run(
              'INSERT INTO email_logs (user_id, email_type, recipient, subject, status) VALUES (?, ?, ?, ?, ?)',
              [decoded.userId, 'order_confirmation', user.email, emailSubject, 'sent'],
              (err) => {
                if (err) reject(err);
                else resolve();
              }
            );
          });
        } catch (emailError) {
          console.error('Failed to send order confirmation email:', emailError);
        }
      } else {
        // Send payment failure email
        const emailSubject = `Payment Failed - Order #${orderId}`;
        const emailHtml = `
          <h1>Payment Failed</h1>
          <p>Dear ${user.first_name},</p>
          <p>Unfortunately, we couldn't process your payment for order #${orderId}.</p>
          <p>Please try again with a different payment method or contact our support team.</p>
          <p>Order total: $${totalAmount.toFixed(2)}</p>
          <p>Best regards,</p>
          <p>The Team</p>
        `;

        try {
          await this.sendEmail(user.email, emailSubject, emailHtml, 'payment_failure');
        } catch (emailError) {
          console.error('Failed to send payment failure email:', emailError);
        }
      }

      // Log analytics event for order creation
      await new Promise((resolve, reject) => {
        db.run(
          'INSERT INTO analytics_events (user_id, event_type, event_data, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)',
          [decoded.userId, 'order_created', JSON.stringify({ 
            orderId, 
            totalAmount, 
            itemCount: items.length,
            paymentMethod: payment_method,
            paymentSuccess: paymentResult.success
          }), req.ip, req.get('User-Agent')],
          (err) => {
            if (err) reject(err);
            else resolve();
          }
        );
      });

      if (paymentResult.success) {
        res.status(201).json({
          message: 'Order created and payment processed successfully',
          order: {
            id: orderId,
            total_amount: totalAmount,
            status: orderStatus,
            payment_status: paymentStatus,
            transaction_id: paymentResult.transactionId
          }
        });
      } else {
        res.status(400).json({
          error: 'Order created but payment failed',
          order: {
            id: orderId,
            total_amount: totalAmount,
            status: orderStatus,
            payment_status: paymentStatus
          },
          payment_error: paymentResult.error
        });
      }

    } catch (error) {
      console.error('Order creation error:', error);
      res.status(500).json({ error: 'Internal server error during order creation' });
    }
  }

  // MASSIVE METHOD THAT HANDLES USER PROFILE UPDATES AND NOTIFICATIONS
  async updateProfile(req, res) {
    try {
      // Extract user from JWT token
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) {
        return res.status(401).json({ error: 'No token provided' });
      }

      let decoded;
      try {
        decoded = jwt.verify(token, this.jwtSecret);
      } catch (jwtError) {
        return res.status(401).json({ error: 'Invalid token' });
      }

      // Input validation
      const schema = Joi.object({
        first_name: Joi.string().max(50),
        last_name: Joi.string().max(50),
        phone: Joi.string().max(20),
        address: Joi.string().max(500),
        email: Joi.string().email()
      });

      const { error, value } = schema.validate(req.body);
      if (error) {
        return res.status(400).json({ error: error.details[0].message });
      }

      // Get current user data
      const currentUser = await new Promise((resolve, reject) => {
        db.get('SELECT * FROM users WHERE id = ?', [decoded.userId], (err, row) => {
          if (err) reject(err);
          else resolve(row);
        });
      });

      if (!currentUser) {
        return res.status(404).json({ error: 'User not found' });
      }

      // Check if email is being changed and if it's already taken
      if (value.email && value.email !== currentUser.email) {
        const existingUser = await new Promise((resolve, reject) => {
          db.get('SELECT * FROM users WHERE email = ? AND id != ?', [value.email, decoded.userId], (err, row) => {
            if (err) reject(err);
            else resolve(row);
          });
        });

        if (existingUser) {
          return res.status(409).json({ error: 'Email already taken by another user' });
        }
      }

      // Build update query dynamically based on provided fields
      const updateFields = [];
      const updateValues = [];
      const changedFields = [];

      Object.keys(value).forEach(key => {
        if (value[key] !== undefined && value[key] !== currentUser[key]) {
          updateFields.push(`${key} = ?`);
          updateValues.push(value[key]);
          changedFields.push({
            field: key,
            old_value: currentUser[key],
            new_value: value[key]
          });
        }
      });

      if (updateFields.length === 0) {
        return res.status(400).json({ error: 'No changes detected' });
      }

      // Add updated_at field
      updateFields.push('updated_at = CURRENT_TIMESTAMP');
      updateValues.push(decoded.userId);

      // Update user profile
      await new Promise((resolve, reject) => {
        db.run(
          `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`,
          updateValues,
          (err) => {
            if (err) reject(err);
            else resolve();
          }
        );
      });

      // Get updated user data
      const updatedUser = await new Promise((resolve, reject) => {
        db.get('SELECT id, username, email, first_name, last_name, phone, address FROM users WHERE id = ?', [decoded.userId], (err, row) => {
          if (err) reject(err);
          else resolve(row);
        });
      });

      // Send profile update notification email
      const emailSubject = 'Profile Updated Successfully';
      const changedFieldsList = changedFields.map(change => 
        `${change.field}: "${change.old_value}" → "${change.new_value}"`
      ).join('<br>');

      const emailHtml = `
        <h1>Profile Updated</h1>
        <p>Dear ${updatedUser.first_name},</p>
        <p>Your profile has been updated successfully.</p>
        
        <h3>Changes Made:</h3>
        <p>${changedFieldsList}</p>
        
        <p>If you didn't make these changes, please contact our support team immediately.</p>
        
        <p>Best regards,</p>
        <p>The Team</p>
      `;

      try {
        await this.sendEmail(updatedUser.email, emailSubject, emailHtml, 'profile_update');

        // Log email send
        await new Promise((resolve, reject) => {
          db.run(
            'INSERT INTO email_logs (user_id, email_type, recipient, subject, status) VALUES (?, ?, ?, ?, ?)',
            [decoded.userId, 'profile_update', updatedUser.email, emailSubject, 'sent'],
            (err) => {
              if (err) reject(err);
              else resolve();
            }
          );
        });
      } catch (emailError) {
        console.error('Failed to send profile update email:', emailError);
      }

      // Log analytics event for profile update
      await new Promise((resolve, reject) => {
        db.run(
          'INSERT INTO analytics_events (user_id, event_type, event_data, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)',
          [decoded.userId, 'profile_updated', JSON.stringify({ 
            changed_fields: changedFields.map(c => c.field),
            change_count: changedFields.length
          }), req.ip, req.get('User-Agent')],
          (err) => {
            if (err) reject(err);
            else resolve();
          }
        );
      });

      res.json({
        message: 'Profile updated successfully',
        user: updatedUser,
        changes_made: changedFields.length
      });

    } catch (error) {
      console.error('Profile update error:', error);
      res.status(500).json({ error: 'Internal server error during profile update' });
    }
  }

  // MASSIVE METHOD THAT HANDLES USER ANALYTICS AND REPORTING
  async getUserAnalytics(req, res) {
    try {
      // Extract user from JWT token
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) {
        return res.status(401).json({ error: 'No token provided' });
      }

      let decoded;
      try {
        decoded = jwt.verify(token, this.jwtSecret);
      } catch (jwtError) {
        return res.status(401).json({ error: 'Invalid token' });
      }

      // Get user basic info
      const user = await new Promise((resolve, reject) => {
        db.get('SELECT id, username, email, first_name, last_name, created_at FROM users WHERE id = ?', [decoded.userId], (err, row) => {
          if (err) reject(err);
          else resolve(row);
        });
      });

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      // Get user's order statistics
      const orderStats = await new Promise((resolve, reject) => {
        db.all(`
          SELECT 
            COUNT(*) as total_orders,
            SUM(total_amount) as total_spent,
            AVG(total_amount) as average_order_value,
            MAX(total_amount) as highest_order,
            MIN(total_amount) as lowest_order
          FROM orders 
          WHERE user_id = ?
        `, [decoded.userId], (err, rows) => {
          if (err) reject(err);
          else resolve(rows[0]);
        });
      });

      // Get order status breakdown
      const orderStatusBreakdown = await new Promise((resolve, reject) => {
        db.all(`
          SELECT 
            status,
            COUNT(*) as count,
            SUM(total_amount) as total_amount
          FROM orders 
          WHERE user_id = ? 
          GROUP BY status
        `, [decoded.userId], (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        });
      });

      // Get recent orders
      const recentOrders = await new Promise((resolve, reject) => {
        db.all(`
          SELECT 
            id,
            total_amount,
            status,
            payment_status,
            created_at
          FROM orders 
          WHERE user_id = ? 
          ORDER BY created_at DESC 
          LIMIT 5
        `, [decoded.userId], (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        });
      });

      // Get email interaction stats
      const emailStats = await new Promise((resolve, reject) => {
        db.all(`
          SELECT 
            email_type,
            COUNT(*) as count,
            SUM(CASE WHEN status = 'sent' THEN 1 ELSE 0 END) as sent_count,
            SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed_count
          FROM email_logs 
          WHERE user_id = ? 
          GROUP BY email_type
        `, [decoded.userId], (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        });
      });

      // Get analytics events summary
      const analyticsEventsSummary = await new Promise((resolve, reject) => {
        db.all(`
          SELECT 
            event_type,
            COUNT(*) as count,
            MAX(created_at) as last_event
          FROM analytics_events 
          WHERE user_id = ? 
          GROUP BY event_type
          ORDER BY count DESC
        `, [decoded.userId], (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        });
      });

      // Get monthly activity for the last 12 months
      const monthlyActivity = await new Promise((resolve, reject) => {
        db.all(`
          SELECT 
            strftime('%Y-%m', created_at) as month,
            COUNT(*) as event_count
          FROM analytics_events 
          WHERE user_id = ? 
            AND created_at >= date('now', '-12 months')
          GROUP BY strftime('%Y-%m', created_at)
          ORDER BY month
        `, [decoded.userId], (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        });
      });

      // Calculate user engagement score (complex algorithm)
      let engagementScore = 0;
      
      // Base score from orders
      const orderScore = Math.min((orderStats.total_orders || 0) * 10, 50);
      engagementScore += orderScore;
      
      // Score from total spent
      const spendingScore = Math.min((orderStats.total_spent || 0) / 10, 30);
      engagementScore += spendingScore;
      
      // Score from analytics events
      const eventsScore = Math.min(analyticsEventsSummary.reduce((sum, event) => sum + event.count, 0), 20);
      engagementScore += eventsScore;
      
      // Normalize to 100
      engagementScore = Math.min(engagementScore, 100);

      // Generate personalized recommendations based on user behavior
      const recommendations = [];
      
      if ((orderStats.total_orders || 0) === 0) {
        recommendations.push({
          type: 'first_purchase',
          message: 'Complete your first purchase to unlock special member benefits!',
          priority: 'high'
        });
      } else if ((orderStats.total_orders || 0) < 5) {
        recommendations.push({
          type: 'frequent_buyer',
          message: 'You\'re on your way to becoming a valued customer! Make 3 more purchases to reach VIP status.',
          priority: 'medium'
        });
      }

      if ((orderStats.average_order_value || 0) < 50) {
        recommendations.push({
          type: 'bundle_deals',
          message: 'Check out our bundle deals to save more on your purchases!',
          priority: 'low'
        });
      }

      // Log this analytics request
      await new Promise((resolve, reject) => {
        db.run(
          'INSERT INTO analytics_events (user_id, event_type, event_data, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)',
          [decoded.userId, 'analytics_viewed', JSON.stringify({ 
            engagement_score: engagementScore,
            total_orders: orderStats.total_orders,
            total_spent: orderStats.total_spent
          }), req.ip, req.get('User-Agent')],
          (err) => {
            if (err) reject(err);
            else resolve();
          }
        );
      });

      res.json({
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          first_name: user.first_name,
          last_name: user.last_name,
          member_since: user.created_at
        },
        engagement_score: Math.round(engagementScore),
        order_statistics: {
          total_orders: orderStats.total_orders || 0,
          total_spent: parseFloat(orderStats.total_spent || 0).toFixed(2),
          average_order_value: parseFloat(orderStats.average_order_value || 0).toFixed(2),
          highest_order: parseFloat(orderStats.highest_order || 0).toFixed(2),
          lowest_order: parseFloat(orderStats.lowest_order || 0).toFixed(2)
        },
        order_status_breakdown: orderStatusBreakdown,
        recent_orders: recentOrders,
        email_statistics: emailStats,
        activity_summary: analyticsEventsSummary,
        monthly_activity: monthlyActivity,
        recommendations: recommendations
      });

    } catch (error) {
      console.error('Analytics error:', error);
      res.status(500).json({ error: 'Internal server error while fetching analytics' });
    }
  }
}

module.exports = new UserController();