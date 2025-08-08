# Node.js Controller Refactoring Workshop Guide

## Initial Setup

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Configure environment variables:**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` file and set a secure JWT secret:
   ```bash
   JWT_SECRET=your-super-secret-jwt-key-change-in-production
   ```

3. **Initialize the database:**
   ```bash
   npm run init-db
   ```

4. **Start the server:**
   ```bash
   npm start
   ```

5. **Verify the server is running:**
   ```bash
   curl http://localhost:3000/health
   ```

## Understanding the Problem

Open `controllers/userController.js` and examine the massive controller. Notice how it handles:

- ✅ Authentication logic (registration, login, JWT tokens)
- ✅ Email sending (welcome emails, order confirmations, profile updates) - *mock service*
- ✅ Payment processing (simulated payment methods) - *mock service*
- ✅ Order management (creation, item handling)
- ✅ Analytics tracking (events, user behavior)
- ✅ Profile management (updates, validation)

This violates the Single Responsibility Principle and makes the code:
- Hard to test
- Difficult to maintain
- Impossible to reuse
- Prone to bugs

## Refactoring Strategy

We'll extract these services:
1. **AuthService** - Handle authentication logic
2. **EmailService** - Manage email communications *(mock service, no external SMTP)*
3. **PaymentService** - Process payments *(mock service, no external payment providers)*
4. **OrderService** - Manage orders and items
5. **AnalyticsService** - Track user behavior
6. **UserProfileService** - Handle profile updates

**Note:** This workshop uses mock services for email and payment processing to focus on refactoring patterns without requiring external dependencies or API configurations.

---

## Step 0: Test Everything Before Refactoring

**IMPORTANT:** Before starting any refactoring, let's verify that everything works correctly. This gives us a baseline to compare against after each step.

### Testing the Application

1. **Start the server in a separate terminal:**
   ```bash
   npm start
   ```

2. **Test basic health check:**
   ```bash
   curl http://localhost:3000/health
   ```
   Expected: `{"status":"OK","message":"Server is running"}`

3. **Test user registration:**
   ```bash
   curl -X POST http://localhost:3000/api/users/register \
     -H "Content-Type: application/json" \
     -d '{
       "username": "testuser1",
       "email": "test1@example.com", 
       "password": "password123",
       "first_name": "Test",
       "last_name": "User"
     }'
   ```
   Expected: Registration success with user data and JWT token
   
   **Check the console** - you should see:
   ```
   📧 [MOCK EMAIL] To: test1@example.com, Subject: Welcome to Our Platform!
   ```

4. **Save the token from registration response and test creating an order:**
   ```bash
   # Replace YOUR_TOKEN_HERE with the actual token from step 3
   export TOKEN="YOUR_TOKEN_HERE"
   
   curl -X POST http://localhost:3000/api/users/orders \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $TOKEN" \
     -d '{
       "items": [
         {"product_name": "Test Product", "price": 29.99, "quantity": 2},
         {"product_name": "Another Product", "price": 15.00, "quantity": 1}
       ],
       "payment_method": "stripe",
       "payment_token": "tok_test_123",
       "shipping_address": "123 Test St, Test City, TC 12345"
     }'
   ```
   Expected: Order creation success with order details
   
   **Check the console** - you should see:
   ```
   💳 [MOCK PAYMENT] Processing $74.98 via stripe
   💳 [MOCK PAYMENT] Success - Transaction ID: stripe_xxx
   📧 [MOCK EMAIL] To: test1@example.com, Subject: Order Confirmation - #1
   ```

5. **Test analytics:**
   ```bash
   curl -X GET http://localhost:3000/api/users/analytics \
     -H "Authorization: Bearer $TOKEN"
   ```
   Expected: Comprehensive analytics data including engagement score, order stats, and recommendations

6. **Test profile update:**
   ```bash
   curl -X PUT http://localhost:3000/api/users/profile \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $TOKEN" \
     -d '{
       "first_name": "Updated Test",
       "last_name": "Updated User"
     }'
   ```
   Expected: Profile update success
   
   **Check the console** - you should see:
   ```
   📧 [MOCK EMAIL] To: test1@example.com, Subject: Profile Updated Successfully
   ```

### Understanding What We Just Tested

The massive controller (`controllers/userController.js`) currently handles **ALL** of these responsibilities:
- **Authentication** (JWT tokens, password hashing)
- **Email notifications** (welcome, order confirmations, profile updates)
- **Payment processing** (mock payment with different methods)
- **Order management** (creation, validation, item handling)
- **Analytics tracking** (events, engagement scoring)
- **Profile management** (updates, validation)

This is exactly what we'll be breaking apart in the following steps!

### How to Verify Refactoring Success

After each refactoring step, repeat these same tests to ensure:
1. **All functionality still works** - same API responses
2. **Mock services still log correctly** - same console output  
3. **No breaking changes** - same behavior, better code organization

**Keep the server running** and the **terminal open** so you can see the mock service logs throughout the refactoring process.

---

## Step 1: Create the Services Directory and AuthService

### GitHub Copilot Prompts:

**First, create the AuthService:**
```
Create a services directory and an AuthService class that handles user authentication. The service should include methods for password hashing, JWT token generation, user validation, and login verification.
```

**Then, refactor the controller:**
```
Now update the UserController to use the AuthService. Replace all password hashing, JWT token generation, and user validation logic in the register() and login() methods with calls to the AuthService. Remove the duplicate authentication code from the controller.
```

<details>
<summary>Click to see the solution</summary>

**Create the services directory:**
```bash
mkdir services
```

**Create `services/authService.js`:**

```javascript
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const { db } = require('../config/database');

class AuthService {
  constructor() {
    this.jwtSecret = process.env.JWT_SECRET || 'dev-fallback-secret-change-in-production';
    this.saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12;
  }

  async hashPassword(password) {
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
  }

  async verifyPassword(password, hashedPassword) {
    return await bcrypt.compare(password, hashedPassword);
  }

  generateToken(user) {
    return jwt.sign(
      { userId: user.id, username: user.username, email: user.email },
      this.jwtSecret,
      { expiresIn: '24h' }
    );
  }

  verifyToken(token) {
    return jwt.verify(token, this.jwtSecret);
  }

  validateRegistrationData(data) {
    const schema = Joi.object({
      username: Joi.string().min(3).max(50).required(),
      email: Joi.string().email().required(),
      password: Joi.string().min(6).required(),
      first_name: Joi.string().max(50).required(),
      last_name: Joi.string().max(50).required(),
      phone: Joi.string().max(20),
      address: Joi.string().max(500)
    });

    return schema.validate(data);
  }

  validateLoginData(data) {
    const schema = Joi.object({
      username: Joi.string().required(),
      password: Joi.string().required()
    });

    return schema.validate(data);
  }

  async findUserByUsernameOrEmail(identifier) {
    return new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE username = ? OR email = ?', [identifier, identifier], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
  }

  async checkUserExists(username, email) {
    return new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, email], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
  }

  async createUser(userData) {
    const { username, email, password, first_name, last_name, phone, address } = userData;
    const hashedPassword = await this.hashPassword(password);

    return new Promise((resolve, reject) => {
      db.run(
        'INSERT INTO users (username, email, password, first_name, last_name, phone, address) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [username, email, hashedPassword, first_name, last_name, phone, address],
        function(err) {
          if (err) reject(err);
          else resolve(this.lastID);
        }
      );
    });
  }

  extractTokenFromHeader(authHeader) {
    return authHeader?.replace('Bearer ', '');
  }
}

module.exports = AuthService;
```

**Now update the controller to use AuthService. In `controllers/userController.js`:**

1. **Import the AuthService at the top:**
```javascript
const AuthService = require('../services/authService');
```

2. **Initialize AuthService in constructor:**
```javascript
constructor() {
  this.authService = new AuthService();
  // Keep existing JWT secret fallback for now
  this.jwtSecret = process.env.JWT_SECRET || 'dev-fallback-secret-change-in-production';
  this.saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12;
}
```

3. **Update the register() method to use AuthService:**
Replace the validation and password hashing sections with:
```javascript
// Validate input using AuthService
const { error, value } = this.authService.validateRegistrationData(req.body);
if (error) {
  return res.status(400).json({ error: error.details[0].message });
}

// Hash password using AuthService
const hashedPassword = await this.authService.hashPassword(value.password);
```

4. **Update token generation in register() method:**
Replace the JWT token generation with:
```javascript
// Generate token using AuthService
const token = this.authService.generateToken(newUser);
```

5. **Update the login() method to use AuthService:**
Replace validation and password verification with:
```javascript
// Validate input using AuthService
const { error, value } = this.authService.validateLoginData(req.body);
if (error) {
  return res.status(400).json({ error: error.details[0].message });
}

// Verify password using AuthService
const validPassword = await this.authService.verifyPassword(value.password, user.password);

// Generate token using AuthService
const token = this.authService.generateToken(user);
```

</details>

### 🧪 Test After Step 1

Before moving to Step 2, **test that authentication still works**:

```bash
# Test registration (use new username/email)
curl -X POST http://localhost:3000/api/users/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser2", 
    "email": "test2@example.com",
    "password": "password123",
    "first_name": "Test2", 
    "last_name": "User2"
  }'

# Test login with the new user
curl -X POST http://localhost:3000/api/users/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser2",
    "password": "password123"
  }'
```

✅ **Expected:** Both should work exactly as before, with welcome email in console

---

## Step 2: Create EmailService

### GitHub Copilot Prompts:

**First, create the EmailService:**
```
Create an EmailService class that handles all email communications including welcome emails, order confirmations, payment failures, and profile update notifications. The service should use a mock email system (no external dependencies) and log email attempts to the database.
```

**Then, refactor the controller:**
```
Update the UserController to use the EmailService. Replace all the sendEmail method calls and email-related logic in register(), createOrder(), and updateProfile() methods with calls to the EmailService methods. Remove the sendEmail method from the controller since it's now handled by the service.
```

<details>
<summary>Click to see the solution</summary>

**Create `services/emailService.js`:**

```javascript
const { db } = require('../config/database');

class EmailService {
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

  async sendEmail(to, subject, html, from = '"Our Platform" <noreply@ourplatform.com>') {
    try {
      await this.emailTransporter.sendMail({
        from,
        to,
        subject,
        html
      });
      return { success: true };
    } catch (error) {
      console.error('Email sending error:', error);
      return { success: false, error: error.message };
    }
  }

  async logEmail(userId, emailType, recipient, subject, status) {
    return new Promise((resolve, reject) => {
      db.run(
        'INSERT INTO email_logs (user_id, email_type, recipient, subject, status) VALUES (?, ?, ?, ?, ?)',
        [userId, emailType, recipient, subject, status],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
  }

  async sendWelcomeEmail(user) {
    const subject = 'Welcome to Our Platform!';
    const html = `
      <h1>Welcome ${user.first_name}!</h1>
      <p>Thank you for registering with our platform. We're excited to have you on board!</p>
      <p>Your username is: ${user.username}</p>
      <p>You can now start exploring our features.</p>
      <br>
      <p>Best regards,</p>
      <p>The Team</p>
    `;

    const result = await this.sendEmail(user.email, subject, html);
    await this.logEmail(user.id, 'welcome', user.email, subject, result.success ? 'sent' : 'failed');
    return result;
  }

  async sendOrderConfirmationEmail(user, order, items) {
    const subject = `Order Confirmation - #${order.id}`;
    const itemsList = items.map(item => `${item.quantity}x ${item.product_name} - $${item.price.toFixed(2)}`).join('<br>');
    
    const html = `
      <h1>Order Confirmed!</h1>
      <p>Dear ${user.first_name},</p>
      <p>Your order #${order.id} has been confirmed and payment has been processed successfully.</p>
      
      <h3>Order Details:</h3>
      <p><strong>Items:</strong><br>${itemsList}</p>
      <p><strong>Total Amount:</strong> $${order.total_amount.toFixed(2)}</p>
      <p><strong>Shipping Address:</strong> ${order.shipping_address}</p>
      <p><strong>Payment Method:</strong> ${order.payment_method}</p>
      <p><strong>Transaction ID:</strong> ${order.transaction_id}</p>
      
      <p>We'll send you tracking information once your order ships.</p>
      
      <p>Thank you for your business!</p>
      <p>The Team</p>
    `;

    const result = await this.sendEmail(user.email, subject, html, '"Our Platform" <orders@ourplatform.com>');
    await this.logEmail(user.id, 'order_confirmation', user.email, subject, result.success ? 'sent' : 'failed');
    return result;
  }

  async sendPaymentFailureEmail(user, order) {
    const subject = `Payment Failed - Order #${order.id}`;
    const html = `
      <h1>Payment Failed</h1>
      <p>Dear ${user.first_name},</p>
      <p>Unfortunately, we couldn't process your payment for order #${order.id}.</p>
      <p>Please try again with a different payment method or contact our support team.</p>
      <p>Order total: $${order.total_amount.toFixed(2)}</p>
      <p>Best regards,</p>
      <p>The Team</p>
    `;

    const result = await this.sendEmail(user.email, subject, html, '"Our Platform" <orders@ourplatform.com>');
    await this.logEmail(user.id, 'payment_failure', user.email, subject, result.success ? 'sent' : 'failed');
    return result;
  }

  async sendProfileUpdateEmail(user, changedFields) {
    const subject = 'Profile Updated Successfully';
    const changedFieldsList = changedFields.map(change => 
      `${change.field}: "${change.old_value}" → "${change.new_value}"`
    ).join('<br>');

    const html = `
      <h1>Profile Updated</h1>
      <p>Dear ${user.first_name},</p>
      <p>Your profile has been updated successfully.</p>
      
      <h3>Changes Made:</h3>
      <p>${changedFieldsList}</p>
      
      <p>If you didn't make these changes, please contact our support team immediately.</p>
      
      <p>Best regards,</p>
      <p>The Team</p>
    `;

    const result = await this.sendEmail(user.email, subject, html, '"Our Platform" <account@ourplatform.com>');
    await this.logEmail(user.id, 'profile_update', user.email, subject, result.success ? 'sent' : 'failed');
    return result;
  }
}

module.exports = EmailService;
```

**Now update the controller to use EmailService. In `controllers/userController.js`:**

1. **Import the EmailService at the top:**
```javascript
const EmailService = require('../services/emailService');
```

2. **Initialize EmailService in constructor:**
```javascript
constructor() {
  this.authService = new AuthService();
  this.emailService = new EmailService();
  // Keep other existing properties...
}
```

3. **Remove the sendEmail method** from the UserController (around line 16-28) since it's now in EmailService

4. **Update all email calls to use the service:**

In `register()` method, replace:
```javascript
await this.sendEmail(newUser.email, emailSubject, emailHtml, 'welcome');
```
With:
```javascript
await this.emailService.sendWelcomeEmail(newUser.email, newUser.first_name);
```

In `createOrder()` method, replace the email sending blocks with:
```javascript
// For successful payment
await this.emailService.sendOrderConfirmationEmail(
  user.email, user.first_name, orderId, items, totalAmount, 
  shipping_address, payment_method, paymentResult.transactionId
);

// For failed payment  
await this.emailService.sendPaymentFailureEmail(
  user.email, user.first_name, orderId, totalAmount
);
```

In `updateProfile()` method, replace:
```javascript
await this.sendEmail(user.email, emailSubject, emailHtml, 'profile_update');
```
With:
```javascript
await this.emailService.sendProfileUpdateEmail(user.email, user.first_name, changedFields);
```

</details>

### 🧪 Test After Step 2

**Test that all email functionality still works**:

```bash
# Test registration - should show welcome email  
curl -X POST http://localhost:3000/api/users/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser3",
    "email": "test3@example.com", 
    "password": "password123",
    "first_name": "Test3",
    "last_name": "User3"
  }'

# Save token and test order - should show payment + order confirmation emails
export TOKEN="[token_from_above]"
curl -X POST http://localhost:3000/api/users/orders \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "items": [{"product_name": "Test", "price": 20.00, "quantity": 1}],
    "payment_method": "stripe", 
    "payment_token": "tok_test",
    "shipping_address": "123 Test St"
  }'

# Test profile update - should show profile update email
curl -X PUT http://localhost:3000/api/users/profile \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"first_name": "Updated3"}'
```

✅ **Expected:** Same email console output as before, but now generated by EmailService

---

## Step 3: Create PaymentService

### GitHub Copilot Prompts:

**First, create the PaymentService:**
```
Create a PaymentService class that handles mock payment processing for different simulated payment methods (credit card, PayPal, bank transfer). The service should simulate payment processing and return standardized results with transaction IDs, without requiring external payment providers.
```

**Then, refactor the controller:**
```
Update the UserController to use the PaymentService. Replace the processPayment method and all payment processing logic in the createOrder() method with calls to the PaymentService. Remove the processPayment method from the controller.
```

<details>
<summary>Click to see the solution</summary>

**Create `services/paymentService.js`:**

```javascript
class PaymentService {
  // Mock payment processing - simulates payment without external services
  async processPayment(paymentMethod, amount, paymentToken) {
    console.log(`💳 [MOCK PAYMENT] Processing $${amount} via ${paymentMethod}`);
    console.log(`💳 [MOCK PAYMENT] Token: ${paymentToken}`);
    
    // Simulate payment processing delay
    await new Promise(resolve => setTimeout(resolve, 200));
    
    // Simulate success/failure (90% success rate for demonstration)
    const success = Math.random() > 0.1;
    
    if (success) {
      const transactionId = `${paymentMethod}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      console.log(`💳 [MOCK PAYMENT] Success - Transaction ID: ${transactionId}`);
      return { success: true, transactionId, method: paymentMethod };
    } else {
      console.log(`💳 [MOCK PAYMENT] Failed - Simulated payment failure`);
      return { success: false, error: 'Payment failed - insufficient funds or invalid payment method', method: paymentMethod };
    }
  }

  validatePaymentData(data) {
    const { payment_method, payment_token } = data;
    
    if (!payment_method || !payment_token) {
      return { valid: false, error: 'Payment method and token are required' };
    }

    const validMethods = ['stripe', 'paypal', 'bank_transfer']; // Simulated payment method types (no external APIs)
    if (!validMethods.includes(payment_method)) {
      return { valid: false, error: 'Invalid payment method' };
    }

    return { valid: true };
  }
}

module.exports = PaymentService;
```

**Now update the controller to use PaymentService. In `controllers/userController.js`:**

1. **Import the PaymentService at the top:**
```javascript
const PaymentService = require('../services/paymentService');
```

2. **Initialize PaymentService in constructor:**
```javascript
constructor() {
  this.authService = new AuthService();
  this.emailService = new EmailService();
  this.paymentService = new PaymentService();
  // Keep other existing properties...
}
```

3. **Remove the processPayment method** from the UserController (around line 30-49) since it's now in PaymentService

4. **Update payment processing in createOrder() method:**

Replace:
```javascript
const paymentResult = await this.processPayment(totalAmount, payment_method, payment_token);
```
With:
```javascript
const paymentResult = await this.paymentService.processPayment(payment_method, totalAmount, payment_token);
```

</details>

### 🧪 Test After Step 3 - Combined Testing

Now we've extracted 3 services! Let's do **comprehensive testing** to make sure everything still works together:

```bash
# Full workflow test - Registration through Order
curl -X POST http://localhost:3000/api/users/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser4",
    "email": "test4@example.com",
    "password": "password123", 
    "first_name": "Test4",
    "last_name": "User4"
  }'

# Extract token from response, then test order creation
export TOKEN="[token_from_above]"
curl -X POST http://localhost:3000/api/users/orders \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "items": [
      {"product_name": "Combined Test Product", "price": 50.00, "quantity": 1}
    ],
    "payment_method": "paypal",
    "payment_token": "paypal_test_token", 
    "shipping_address": "456 Combined Test Ave"
  }'
```

✅ **Expected console output:**
```
📧 [MOCK EMAIL] Welcome email...
💳 [MOCK PAYMENT] Processing $50.00 via paypal...
💳 [MOCK PAYMENT] Success - Transaction ID: paypal_xxx
📧 [MOCK EMAIL] Order Confirmation email...
```

The architecture is improving! **3 services extracted**, controller getting smaller. 📈

---

## Step 4: Create OrderService

### GitHub Copilot Prompts:

**First, create the OrderService:**
```
Create an OrderService class that handles order creation, order item management, and order status updates. The service should validate order data, calculate totals, and manage order items in the database.
```

**Then, refactor the controller:**
```
Update the UserController to use the OrderService. Replace all order validation, order creation, order item insertion, and order retrieval logic in the createOrder() and getUserAnalytics() methods with calls to the OrderService. Remove the order management helper methods from the controller.
```

<details>
<summary>Click to see the solution</summary>

**Create `services/orderService.js`:**

```javascript
const Joi = require('joi');
const { db } = require('../config/database');

class OrderService {
  validateOrderData(data) {
    const schema = Joi.object({
      items: Joi.array().items(
        Joi.object({
          product_name: Joi.string().required(),
          quantity: Joi.number().integer().min(1).required(),
          price: Joi.number().min(0).required()
        })
      ).min(1).required(),
      shipping_address: Joi.string().required(),
      payment_method: Joi.string().valid('stripe', 'paypal', 'bank_transfer').required(), // Simulated payment types (no external APIs)
      payment_token: Joi.string().required()
    });

    return schema.validate(data);
  }

  calculateOrderTotal(items) {
    return items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
  }

  async createOrder(userId, orderData) {
    const { items, shipping_address, payment_method } = orderData;
    const totalAmount = this.calculateOrderTotal(items);

    return new Promise((resolve, reject) => {
      db.run(
        'INSERT INTO orders (user_id, total_amount, shipping_address, payment_method) VALUES (?, ?, ?, ?)',
        [userId, totalAmount, shipping_address, payment_method],
        function(err) {
          if (err) reject(err);
          else resolve({
            id: this.lastID,
            user_id: userId,
            total_amount: totalAmount,
            shipping_address,
            payment_method,
            status: 'pending',
            payment_status: 'pending'
          });
        }
      );
    });
  }

  async addOrderItems(orderId, items) {
    const promises = items.map(item => {
      return new Promise((resolve, reject) => {
        db.run(
          'INSERT INTO order_items (order_id, product_name, quantity, price) VALUES (?, ?, ?, ?)',
          [orderId, item.product_name, item.quantity, item.price],
          (err) => {
            if (err) reject(err);
            else resolve();
          }
        );
      });
    });

    await Promise.all(promises);
  }

  async updateOrderStatus(orderId, status, paymentStatus = null, transactionId = null) {
    let query = 'UPDATE orders SET status = ?, updated_at = CURRENT_TIMESTAMP';
    let params = [status];

    if (paymentStatus) {
      query += ', payment_status = ?';
      params.push(paymentStatus);
    }

    query += ' WHERE id = ?';
    params.push(orderId);

    return new Promise((resolve, reject) => {
      db.run(query, params, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  async getOrderById(orderId) {
    return new Promise((resolve, reject) => {
      db.get('SELECT * FROM orders WHERE id = ?', [orderId], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
  }

  async getOrderItems(orderId) {
    return new Promise((resolve, reject) => {
      db.all('SELECT * FROM order_items WHERE order_id = ?', [orderId], (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
  }

  async getUserOrders(userId, limit = 10) {
    return new Promise((resolve, reject) => {
      db.all(
        'SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC LIMIT ?',
        [userId, limit],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });
  }

  async getOrderStatistics(userId) {
    return new Promise((resolve, reject) => {
      db.get(`
        SELECT 
          COUNT(*) as total_orders,
          SUM(total_amount) as total_spent,
          AVG(total_amount) as average_order_value,
          MAX(total_amount) as highest_order,
          MIN(total_amount) as lowest_order
        FROM orders 
        WHERE user_id = ?
      `, [userId], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
  }

  async getOrderStatusBreakdown(userId) {
    return new Promise((resolve, reject) => {
      db.all(`
        SELECT 
          status,
          COUNT(*) as count,
          SUM(total_amount) as total_amount
        FROM orders 
        WHERE user_id = ? 
        GROUP BY status
      `, [userId], (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
  }
}

module.exports = OrderService;
```

**Now update the controller to use OrderService. In `controllers/userController.js`:**

1. **Import the OrderService at the top:**
```javascript
const OrderService = require('../services/orderService');
```

2. **Initialize OrderService in constructor:**
```javascript
constructor() {
  this.authService = new AuthService();
  this.emailService = new EmailService();
  this.paymentService = new PaymentService();
  this.orderService = new OrderService();
  // Keep other existing properties...
}
```

3. **Remove these helper methods** from the UserController (they're now in OrderService):
   - `getOrderItems(orderId)`
   - `getUserOrders(userId, limit)`
   - `getOrderStatistics(userId)`
   - `getOrderStatusBreakdown(userId)`

4. **Update the createOrder() method:**

Replace the order validation:
```javascript
// Old validation code...
```
With:
```javascript
const { error, value } = this.orderService.validateOrderData(req.body);
if (error) {
  return res.status(400).json({ error: error.details[0].message });
}
```

Replace order creation and item insertion with:
```javascript
const { orderId, totalAmount } = await this.orderService.createOrder(
  decoded.userId, value.items, value.shipping_address, payment_method
);
```

5. **Update getUserAnalytics() method:**

Replace order statistics calls:
```javascript
const orderStats = await this.orderService.getOrderStatistics(decoded.userId);
const orderStatusBreakdown = await this.orderService.getOrderStatusBreakdown(decoded.userId);
const recentOrders = await this.orderService.getUserOrders(decoded.userId, 5);
```

</details>

---

## Step 5: Create AnalyticsService

### GitHub Copilot Prompts:

**First, create the AnalyticsService:**
```
Create an AnalyticsService class that handles user behavior tracking, event logging, and analytics data retrieval. The service should track various user events and provide analytics summaries and engagement scoring.
```

**Then, refactor the controller:**
```
Update the UserController to use the AnalyticsService. Replace all analytics event logging, engagement score calculation, and analytics data retrieval in register(), createOrder(), updateProfile(), and getUserAnalytics() methods with calls to the AnalyticsService.
```

<details>
<summary>Click to see the solution</summary>

**Create `services/analyticsService.js`:**

```javascript
const { db } = require('../config/database');

class AnalyticsService {
  async logEvent(userId, eventType, eventData, ipAddress, userAgent) {
    return new Promise((resolve, reject) => {
      db.run(
        'INSERT INTO analytics_events (user_id, event_type, event_data, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)',
        [userId, eventType, JSON.stringify(eventData), ipAddress, userAgent],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
  }

  async logUserRegistration(userId, userData, ipAddress, userAgent) {
    const eventData = {
      username: userData.username,
      email: userData.email
    };
    return this.logEvent(userId, 'user_registration', eventData, ipAddress, userAgent);
  }

  async logSuccessfulLogin(userId, username, ipAddress, userAgent) {
    return this.logEvent(userId, 'successful_login', { username }, ipAddress, userAgent);
  }

  async logFailedLoginAttempt(userId, attemptedUsername, ipAddress, userAgent) {
    const eventType = userId ? 'failed_login_invalid_password' : 'failed_login_attempt';
    const eventData = userId ? { username: attemptedUsername } : { attempted_username: attemptedUsername };
    return this.logEvent(userId, eventType, eventData, ipAddress, userAgent);
  }

  async logOrderCreation(userId, orderData, ipAddress, userAgent) {
    const eventData = {
      orderId: orderData.orderId,
      totalAmount: orderData.totalAmount,
      itemCount: orderData.itemCount,
      paymentMethod: orderData.paymentMethod,
      paymentSuccess: orderData.paymentSuccess
    };
    return this.logEvent(userId, 'order_created', eventData, ipAddress, userAgent);
  }

  async logProfileUpdate(userId, changedFields, ipAddress, userAgent) {
    const eventData = {
      changed_fields: changedFields.map(c => c.field),
      change_count: changedFields.length
    };
    return this.logEvent(userId, 'profile_updated', eventData, ipAddress, userAgent);
  }

  async logAnalyticsViewed(userId, analyticsData, ipAddress, userAgent) {
    const eventData = {
      engagement_score: analyticsData.engagement_score,
      total_orders: analyticsData.total_orders,
      total_spent: analyticsData.total_spent
    };
    return this.logEvent(userId, 'analytics_viewed', eventData, ipAddress, userAgent);
  }

  async getEventsSummary(userId) {
    return new Promise((resolve, reject) => {
      db.all(`
        SELECT 
          event_type,
          COUNT(*) as count,
          MAX(created_at) as last_event
        FROM analytics_events 
        WHERE user_id = ? 
        GROUP BY event_type
        ORDER BY count DESC
      `, [userId], (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
  }

  async getMonthlyActivity(userId, months = 12) {
    return new Promise((resolve, reject) => {
      db.all(`
        SELECT 
          strftime('%Y-%m', created_at) as month,
          COUNT(*) as event_count
        FROM analytics_events 
        WHERE user_id = ? 
          AND created_at >= date('now', '-${months} months')
        GROUP BY strftime('%Y-%m', created_at)
        ORDER BY month
      `, [userId], (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
  }

  async getEmailStatistics(userId) {
    return new Promise((resolve, reject) => {
      db.all(`
        SELECT 
          email_type,
          COUNT(*) as count,
          SUM(CASE WHEN status = 'sent' THEN 1 ELSE 0 END) as sent_count,
          SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed_count
        FROM email_logs 
        WHERE user_id = ? 
        GROUP BY email_type
      `, [userId], (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
  }

  calculateEngagementScore(orderStats, eventsSummary) {
    let engagementScore = 0;
    
    // Base score from orders
    const orderScore = Math.min((orderStats.total_orders || 0) * 10, 50);
    engagementScore += orderScore;
    
    // Score from total spent
    const spendingScore = Math.min((orderStats.total_spent || 0) / 10, 30);
    engagementScore += spendingScore;
    
    // Score from analytics events
    const eventsScore = Math.min(eventsSummary.reduce((sum, event) => sum + event.count, 0), 20);
    engagementScore += eventsScore;
    
    // Normalize to 100
    return Math.min(engagementScore, 100);
  }

  generateRecommendations(orderStats) {
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

    return recommendations;
  }
}

module.exports = AnalyticsService;
```

**Now update the controller to use AnalyticsService. In `controllers/userController.js`:**

1. **Import the AnalyticsService at the top:**
```javascript
const AnalyticsService = require('../services/analyticsService');
```

2. **Initialize AnalyticsService in constructor:**
```javascript
constructor() {
  this.authService = new AuthService();
  this.emailService = new EmailService();
  this.paymentService = new PaymentService();
  this.orderService = new OrderService();
  this.analyticsService = new AnalyticsService();
  // Keep other existing properties...
}
```

3. **Update analytics logging in register() method:**

Replace:
```javascript
// Old analytics logging code...
```
With:
```javascript
await this.analyticsService.logUserRegistration(newUser.id, newUser, req.ip, req.get('User-Agent'));
```

4. **Update analytics logging in createOrder() method:**

Replace:
```javascript
// Old analytics event logging...
```
With:
```javascript
await this.analyticsService.logEvent(
  decoded.userId, 'order_created', 
  { orderId, totalAmount, itemCount: items.length, paymentMethod: payment_method, paymentSuccess: paymentResult.success },
  req.ip, req.get('User-Agent')
);
```

5. **Update analytics logging in updateProfile() method:**

Replace analytics logging with:
```javascript
await this.analyticsService.logEvent(
  decoded.userId, 'profile_updated',
  { fields_changed: changedFields.join(', '), change_count: changedFields.length },
  req.ip, req.get('User-Agent')
);
```

6. **Update getUserAnalytics() method:**

Replace all analytics retrieval code with:
```javascript
const analyticsData = await this.analyticsService.getUserAnalytics(decoded.userId, orderStats);
```

</details>

### 🧪 Test After Step 5

**Test analytics functionality**:

```bash
# Create a new user and test the full analytics workflow
curl -X POST http://localhost:3000/api/users/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "analyticstest",
    "email": "analytics@example.com",
    "password": "password123",
    "first_name": "Analytics",
    "last_name": "Test"
  }'

# Extract token and test analytics (should show registration event)
export TOKEN="[token_from_above]"
curl -X GET http://localhost:3000/api/users/analytics \
  -H "Authorization: Bearer $TOKEN"
```

✅ **Expected:** Analytics response with engagement score, order stats, and activity summary

---

## Step 6: Create UserProfileService

### GitHub Copilot Prompts:

**First, create the UserProfileService:**
```
Create a UserProfileService class that handles user profile operations including profile updates, validation, and user data retrieval. The service should track field changes and validate profile updates.
```

**Then, refactor the controller:**
```
Update the UserController to use the UserProfileService. Replace all profile validation, user data retrieval, profile update logic, and field change tracking in the updateProfile() method with calls to the UserProfileService. Also update getUserAnalytics() to use the service for user data retrieval.
```

<details>
<summary>Click to see the solution</summary>

**Create `services/userProfileService.js`:**

```javascript
const Joi = require('joi');
const { db } = require('../config/database');

class UserProfileService {
  validateProfileUpdate(data) {
    const schema = Joi.object({
      first_name: Joi.string().max(50),
      last_name: Joi.string().max(50),
      phone: Joi.string().max(20),
      address: Joi.string().max(500),
      email: Joi.string().email()
    });

    return schema.validate(data);
  }

  async getUserById(userId) {
    return new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE id = ?', [userId], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
  }

  async getUserByIdSafe(userId) {
    return new Promise((resolve, reject) => {
      db.get(
        'SELECT id, username, email, first_name, last_name, phone, address, created_at FROM users WHERE id = ?',
        [userId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });
  }

  async checkEmailAvailability(email, excludeUserId) {
    return new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM users WHERE email = ? AND id != ?',
        [email, excludeUserId],
        (err, row) => {
          if (err) reject(err);
          else resolve(!row); // true if email is available
        }
      );
    });
  }

  detectChanges(currentUser, updateData) {
    const changedFields = [];

    Object.keys(updateData).forEach(key => {
      if (updateData[key] !== undefined && updateData[key] !== currentUser[key]) {
        changedFields.push({
          field: key,
          old_value: currentUser[key],
          new_value: updateData[key]
        });
      }
    });

    return changedFields;
  }

  async updateUserProfile(userId, updateData) {
    const updateFields = [];
    const updateValues = [];

    Object.keys(updateData).forEach(key => {
      if (updateData[key] !== undefined) {
        updateFields.push(`${key} = ?`);
        updateValues.push(updateData[key]);
      }
    });

    if (updateFields.length === 0) {
      throw new Error('No fields to update');
    }

    // Add updated_at field
    updateFields.push('updated_at = CURRENT_TIMESTAMP');
    updateValues.push(userId);

    return new Promise((resolve, reject) => {
      db.run(
        `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`,
        updateValues,
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
  }

  async getUserMembershipInfo(userId) {
    const user = await this.getUserByIdSafe(userId);
    if (!user) return null;

    return {
      id: user.id,
      username: user.username,
      email: user.email,
      first_name: user.first_name,
      last_name: user.last_name,
      member_since: user.created_at
    };
  }

  buildProfileUpdateSummary(changedFields) {
    return {
      changes_made: changedFields.length,
      changed_fields: changedFields.map(c => c.field),
      details: changedFields
    };
  }
}

module.exports = UserProfileService;
```

**Now update the controller to use UserProfileService. In `controllers/userController.js`:**

1. **Import the UserProfileService at the top:**
```javascript
const UserProfileService = require('../services/userProfileService');
```

2. **Initialize UserProfileService in constructor:**
```javascript
constructor() {
  this.authService = new AuthService();
  this.emailService = new EmailService();
  this.paymentService = new PaymentService();
  this.orderService = new OrderService();
  this.analyticsService = new AnalyticsService();
  this.userProfileService = new UserProfileService();
  // Keep other existing properties...
}
```

3. **Update the updateProfile() method:**

Replace profile validation:
```javascript
const { error, value } = this.userProfileService.validateProfileUpdate(req.body);
if (error) {
  return res.status(400).json({ error: error.details[0].message });
}
```

Replace user retrieval:
```javascript
const user = await this.userProfileService.getUserById(decoded.userId);
```

Replace profile update logic:
```javascript
const updateResult = await this.userProfileService.updateProfile(decoded.userId, value);
```

4. **Update getUserAnalytics() method:**

Replace user data retrieval:
```javascript
const user = await this.userProfileService.getUserById(decoded.userId);
```

</details>

### 🧪 Final Service Testing 

All 6 services are now created! **Time for comprehensive testing** to ensure the refactored application works perfectly:

```bash
# Complete end-to-end test workflow
echo "=== Registration Test ==="
curl -X POST http://localhost:3000/api/users/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "finaltest",
    "email": "final@example.com",
    "password": "password123",
    "first_name": "Final",
    "last_name": "Test"
  }'

echo -e "\n=== Profile Update Test ==="
export TOKEN="[token_from_above]"
curl -X PUT http://localhost:3000/api/users/profile \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"first_name": "Updated Final"}'

echo -e "\n=== Order Creation Test ==="  
curl -X POST http://localhost:3000/api/users/orders \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "items": [{"product_name": "Final Product", "price": 99.99, "quantity": 1}],
    "payment_method": "bank_transfer",
    "payment_token": "bank_test",
    "shipping_address": "999 Final Test Blvd"
  }'

echo -e "\n=== Analytics Test ==="
curl -X GET http://localhost:3000/api/users/analytics \
  -H "Authorization: Bearer $TOKEN"
```

✅ **Expected:** All functionality working with proper service separation!

---

## Step 7: Final Controller Refactoring (Optional - Advanced)

**Note:** If you've been following Steps 1-6 and updating the controller incrementally, you can skip this step. This step shows the complete refactored controller for reference.

### GitHub Copilot Prompt:
```
Create a completely refactored UserController that uses all the newly created services. Replace the monolithic methods with clean, focused methods that delegate business logic to the appropriate services. The controller should only handle HTTP requests/responses and coordinate between services.
```

<details>
<summary>Click to see the solution</summary>

**Create `controllers/userControllerRefactored.js`:**

```javascript
const AuthService = require('../services/authService');
const EmailService = require('../services/emailService');
const PaymentService = require('../services/paymentService');
const OrderService = require('../services/orderService');
const AnalyticsService = require('../services/analyticsService');
const UserProfileService = require('../services/userProfileService');

class UserControllerRefactored {
  constructor() {
    this.authService = new AuthService();
    this.emailService = new EmailService();
    this.paymentService = new PaymentService();
    this.orderService = new OrderService();
    this.analyticsService = new AnalyticsService();
    this.userProfileService = new UserProfileService();
  }

  async register(req, res) {
    try {
      // Validate input
      const { error, value } = this.authService.validateRegistrationData(req.body);
      if (error) {
        return res.status(400).json({ error: error.details[0].message });
      }

      const { username, email } = value;

      // Check if user exists
      const existingUser = await this.authService.checkUserExists(username, email);
      if (existingUser) {
        return res.status(409).json({ error: 'User already exists with this username or email' });
      }

      // Create user
      const userId = await this.authService.createUser(value);

      // Generate token
      const token = this.authService.generateToken({ id: userId, username, email });

      // Log analytics
      await this.analyticsService.logUserRegistration(userId, value, req.ip, req.get('User-Agent'));

      // Send welcome email
      await this.emailService.sendWelcomeEmail({
        id: userId,
        username,
        email,
        first_name: value.first_name
      });

      res.status(201).json({
        message: 'User registered successfully',
        user: {
          id: userId,
          username,
          email,
          first_name: value.first_name,
          last_name: value.last_name
        },
        token
      });

    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({ error: 'Internal server error during registration' });
    }
  }

  async login(req, res) {
    try {
      // Validate input
      const { error, value } = this.authService.validateLoginData(req.body);
      if (error) {
        return res.status(400).json({ error: error.details[0].message });
      }

      const { username, password } = value;

      // Find user
      const user = await this.authService.findUserByUsernameOrEmail(username);
      if (!user) {
        await this.analyticsService.logFailedLoginAttempt(null, username, req.ip, req.get('User-Agent'));
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Verify password
      const isPasswordValid = await this.authService.verifyPassword(password, user.password);
      if (!isPasswordValid) {
        await this.analyticsService.logFailedLoginAttempt(user.id, user.username, req.ip, req.get('User-Agent'));
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Generate token
      const token = this.authService.generateToken(user);

      // Log successful login
      await this.analyticsService.logSuccessfulLogin(user.id, user.username, req.ip, req.get('User-Agent'));

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

  async createOrder(req, res) {
    try {
      // Authenticate user
      const token = this.authService.extractTokenFromHeader(req.headers.authorization);
      if (!token) {
        return res.status(401).json({ error: 'No token provided' });
      }

      let decoded;
      try {
        decoded = this.authService.verifyToken(token);
      } catch (jwtError) {
        return res.status(401).json({ error: 'Invalid token' });
      }

      // Validate order data
      const { error, value } = this.orderService.validateOrderData(req.body);
      if (error) {
        return res.status(400).json({ error: error.details[0].message });
      }

      const { items, shipping_address, payment_method, payment_token } = value;

      // Validate payment data
      const paymentValidation = this.paymentService.validatePaymentData(value);
      if (!paymentValidation.valid) {
        return res.status(400).json({ error: paymentValidation.error });
      }

      // Create order
      const order = await this.orderService.createOrder(decoded.userId, value);
      
      // Add order items
      await this.orderService.addOrderItems(order.id, items);

      // Process payment
      const paymentResult = await this.paymentService.processPayment(
        payment_method,
        order.total_amount,
        payment_token
      );

      // Update order status
      const paymentStatus = paymentResult.success ? 'completed' : 'failed';
      const orderStatus = paymentResult.success ? 'confirmed' : 'payment_failed';
      
      await this.orderService.updateOrderStatus(order.id, orderStatus, paymentStatus);

      // Get user for email
      const user = await this.userProfileService.getUserById(decoded.userId);

      // Send appropriate email
      if (paymentResult.success) {
        await this.emailService.sendOrderConfirmationEmail(
          user,
          { ...order, transaction_id: paymentResult.transactionId },
          items
        );
      } else {
        await this.emailService.sendPaymentFailureEmail(user, order);
      }

      // Log analytics
      await this.analyticsService.logOrderCreation(decoded.userId, {
        orderId: order.id,
        totalAmount: order.total_amount,
        itemCount: items.length,
        paymentMethod: payment_method,
        paymentSuccess: paymentResult.success
      }, req.ip, req.get('User-Agent'));

      if (paymentResult.success) {
        res.status(201).json({
          message: 'Order created and payment processed successfully',
          order: {
            id: order.id,
            total_amount: order.total_amount,
            status: orderStatus,
            payment_status: paymentStatus,
            transaction_id: paymentResult.transactionId
          }
        });
      } else {
        res.status(400).json({
          error: 'Order created but payment failed',
          order: {
            id: order.id,
            total_amount: order.total_amount,
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

  async updateProfile(req, res) {
    try {
      // Authenticate user
      const token = this.authService.extractTokenFromHeader(req.headers.authorization);
      if (!token) {
        return res.status(401).json({ error: 'No token provided' });
      }

      let decoded;
      try {
        decoded = this.authService.verifyToken(token);
      } catch (jwtError) {
        return res.status(401).json({ error: 'Invalid token' });
      }

      // Validate input
      const { error, value } = this.userProfileService.validateProfileUpdate(req.body);
      if (error) {
        return res.status(400).json({ error: error.details[0].message });
      }

      // Get current user
      const currentUser = await this.userProfileService.getUserById(decoded.userId);
      if (!currentUser) {
        return res.status(404).json({ error: 'User not found' });
      }

      // Check email availability if email is being changed
      if (value.email && value.email !== currentUser.email) {
        const emailAvailable = await this.userProfileService.checkEmailAvailability(value.email, decoded.userId);
        if (!emailAvailable) {
          return res.status(409).json({ error: 'Email already taken by another user' });
        }
      }

      // Detect changes
      const changedFields = this.userProfileService.detectChanges(currentUser, value);
      if (changedFields.length === 0) {
        return res.status(400).json({ error: 'No changes detected' });
      }

      // Update profile
      await this.userProfileService.updateUserProfile(decoded.userId, value);

      // Get updated user
      const updatedUser = await this.userProfileService.getUserByIdSafe(decoded.userId);

      // Send notification email
      await this.emailService.sendProfileUpdateEmail(updatedUser, changedFields);

      // Log analytics
      await this.analyticsService.logProfileUpdate(decoded.userId, changedFields, req.ip, req.get('User-Agent'));

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

  async getUserAnalytics(req, res) {
    try {
      // Authenticate user
      const token = this.authService.extractTokenFromHeader(req.headers.authorization);
      if (!token) {
        return res.status(401).json({ error: 'No token provided' });
      }

      let decoded;
      try {
        decoded = this.authService.verifyToken(token);
      } catch (jwtError) {
        return res.status(401).json({ error: 'Invalid token' });
      }

      // Get user membership info
      const user = await this.userProfileService.getUserMembershipInfo(decoded.userId);
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      // Get analytics data
      const [
        orderStats,
        orderStatusBreakdown,
        recentOrders,
        emailStats,
        eventsSummary,
        monthlyActivity
      ] = await Promise.all([
        this.orderService.getOrderStatistics(decoded.userId),
        this.orderService.getOrderStatusBreakdown(decoded.userId),
        this.orderService.getUserOrders(decoded.userId, 5),
        this.analyticsService.getEmailStatistics(decoded.userId),
        this.analyticsService.getEventsSummary(decoded.userId),
        this.analyticsService.getMonthlyActivity(decoded.userId)
      ]);

      // Calculate engagement score
      const engagementScore = this.analyticsService.calculateEngagementScore(orderStats, eventsSummary);

      // Generate recommendations
      const recommendations = this.analyticsService.generateRecommendations(orderStats);

      // Log analytics view
      await this.analyticsService.logAnalyticsViewed(decoded.userId, {
        engagement_score: engagementScore,
        total_orders: orderStats.total_orders,
        total_spent: orderStats.total_spent
      }, req.ip, req.get('User-Agent'));

      res.json({
        user,
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
        activity_summary: eventsSummary,
        monthly_activity: monthlyActivity,
        recommendations
      });

    } catch (error) {
      console.error('Analytics error:', error);
      res.status(500).json({ error: 'Internal server error while fetching analytics' });
    }
  }
}

module.exports = new UserControllerRefactored();
```

</details>



## Step 8: Final Verification & Testing

**You've successfully extracted 6 services!** 🎉 Now let's thoroughly verify that everything works correctly.

### Complete Application Test

Run this comprehensive test to verify all functionality:

```bash
echo "🧪 COMPREHENSIVE WORKSHOP TESTING"
echo "=================================="

# Test 1: Health Check
echo -e "\n1️⃣ Testing Health Endpoint..."
curl -s http://localhost:3000/health | jq .

# Test 2: User Registration  
echo -e "\n2️⃣ Testing User Registration..."
REGISTER_RESPONSE=$(curl -s -X POST http://localhost:3000/api/users/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "workshop_final",
    "email": "workshop.final@example.com",
    "password": "password123",
    "first_name": "Workshop",
    "last_name": "Final"
  }')

echo "$REGISTER_RESPONSE" | jq .
TOKEN=$(echo "$REGISTER_RESPONSE" | jq -r '.token')

# Test 3: Profile Update
echo -e "\n3️⃣ Testing Profile Update..."
curl -s -X PUT http://localhost:3000/api/users/profile \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "first_name": "Workshop Updated",
    "last_name": "Final Updated"
  }' | jq .

# Test 4: Order Creation
echo -e "\n4️⃣ Testing Order Creation..."
curl -s -X POST http://localhost:3000/api/users/orders \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "items": [
      {"product_name": "Workshop Product A", "price": 49.99, "quantity": 2},
      {"product_name": "Workshop Product B", "price": 29.99, "quantity": 1}
    ],
    "payment_method": "stripe",
    "payment_token": "tok_workshop_test",
    "shipping_address": "123 Workshop Lane, Testing City, WS 12345"
  }' | jq .

# Test 5: Analytics
echo -e "\n5️⃣ Testing Analytics..."
curl -s -X GET http://localhost:3000/api/users/analytics \
  -H "Authorization: Bearer $TOKEN" | jq .

echo "Check the server console for mock email and payment logs."
```

### What to Look For

**In the API responses:**
- ✅ All endpoints return proper JSON responses
- ✅ Registration returns user data + JWT token
- ✅ Orders return order confirmation with payment details  
- ✅ Analytics returns comprehensive user data

**In the server console:**
- ✅ `📧 [MOCK EMAIL]` logs for welcome, order confirmation, and profile update emails
- ✅ `💳 [MOCK PAYMENT]` logs showing payment processing

**Code Quality Improvements:**
- ✅ **6 focused services** instead of 1 massive controller
- ✅ **Single Responsibility Principle** - each service has one clear purpose
- ✅ **Dependency Injection** - services can be easily tested and mocked
- ✅ **Reusability** - services can be used by other controllers
- ✅ **Maintainability** - easier to modify and extend specific functionality

---

## Step 9: Before vs After Comparison

### Original Monolithic Controller
```bash
# Check the size of the original controller
wc -l controllers/userController.js
grep -c "async " controllers/userController.js
```

**Original Controller Issues:**
- 📊 **860+ lines** of code in a single file
- 🔄 **6+ responsibilities** mixed together
- 🧪 **Hard to test** - everything tightly coupled
- 🔧 **Hard to maintain** - changes affect multiple concerns
- ♻️ **No reusability** - logic locked in controller

### Refactored Service Architecture
```bash  
# Check the services we created
echo "Service files created:"
ls -la services/
echo -e "\nTotal lines in all services:"
wc -l services/*.js | tail -1
```

**Refactored Architecture Benefits:**
- 📊 **Distributed code** across focused service files
- 🎯 **Single responsibility** per service
- 🧪 **Highly testable** - each service can be tested independently
- 🔧 **Easy to maintain** - changes isolated to specific services
- ♻️ **Reusable** - services can be used anywhere in the application
- 🔒 **Mock services** - no external dependencies needed
- 🔐 **Environment-based config** - secure credential management

### Service Responsibilities

| Service | Responsibility | Original Lines | Refactored |
|---------|---------------|----------------|------------|
| **AuthService** | Authentication, JWT, password hashing | ~50 lines | ✅ Isolated |
| **EmailService** | Mock email sending, logging | ~30 lines | ✅ Isolated |
| **PaymentService** | Mock payment processing | ~40 lines | ✅ Isolated |
| **OrderService** | Order management, validation | ~150 lines | ✅ Isolated |
| **AnalyticsService** | Event tracking, analytics | ~200 lines | ✅ Isolated |
| **UserProfileService** | Profile updates, user data | ~60 lines | ✅ Isolated |
| **Controller** | HTTP handling, coordination | ~300 lines | ✅ Clean & Focused |

---

## Step 10: Workshop Summary & Next Steps

### 🎯 What You've Accomplished

**Service Extraction Mastery:**
- ✅ Identified responsibilities in monolithic code
- ✅ Used GitHub Copilot effectively for refactoring
- ✅ Extracted 6 focused, reusable services  
- ✅ Maintained full functionality throughout refactoring
- ✅ Implemented mock services for educational focus
- ✅ Applied secure environment-based configuration

**Architecture Improvements:**
- ✅ **Better Separation of Concerns** - each service has a single responsibility
- ✅ **Improved Testability** - services can be unit tested independently
- ✅ **Enhanced Maintainability** - changes are isolated to specific services
- ✅ **Increased Reusability** - services can be used across the application
- ✅ **Mock Service Pattern** - external dependencies replaced with controllable mocks

### 🚀 Real-World Applications

**Use these patterns in production for:**
- Breaking down large controllers in existing applications
- Extracting payment processing logic
- Separating authentication concerns
- Organizing email/notification systems
- Implementing analytics and tracking
- Managing user profile operations

**Next Steps for Production:**
1. **Add Unit Tests** - Test each service independently
2. **Add Integration Tests** - Test service interactions
3. **Replace Mock Services** - Integrate real email/payment providers when needed
4. **Add Error Handling** - Implement comprehensive error handling
5. **Add Logging** - Implement structured logging
6. **Add Monitoring** - Track service performance and errors

### 🧠 GitHub Copilot Tips Learned

**Effective Prompting:**
- ✅ Be specific about the responsibility of each service
- ✅ Mention existing code to extract from
- ✅ Ask for both creation AND controller refactoring
- ✅ Request mock implementations for learning purposes

**Best Practices:**
- ✅ Test after each service extraction
- ✅ Refactor incrementally, not all at once
- ✅ Maintain functionality while improving structure
- ✅ Use environment variables for configuration

---

## 🎉 Congratulations!

You've successfully refactored a monolithic Node.js controller into a clean, service-oriented architecture using GitHub Copilot! The application now follows modern design patterns while maintaining all functionality and using secure configuration practices.

**Keep the services in mind** for your next Node.js project - this pattern scales beautifully as applications grow! 🚀
