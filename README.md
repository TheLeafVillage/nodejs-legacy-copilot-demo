# Node.js Legacy Controller Refactoring Workshop

This workshop teaches developers how to use GitHub Copilot to refactor a large, monolithic controller into smaller, reusable services. This is a common real-world scenario that backend developers face when working with legacy codebases.

## Workshop Overview

You'll learn how to:
- Identify responsibilities in a large controller
- Use GitHub Copilot to extract services systematically
- Maintain functionality while improving code organization
- Apply dependency injection patterns
- Test refactored code

## Prerequisites

- Basic knowledge of Node.js and Express
- GitHub Copilot enabled in your IDE
- Understanding of MVC patterns

## Getting Started

This repository contains a Node.js/Express application with a deliberately large, monolithic `UserController` that handles multiple responsibilities:

- User authentication (registration, login)
- User profile management
- Order processing and payment
- Email notifications
- Analytics tracking

## Setup Instructions

1. **Clone and install dependencies:**

   ```bash
   npm install
   ```

2. **Configure environment variables:**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` file to set your configuration:
   - `JWT_SECRET`: Your secret key for JWT tokens (required in production)
   - `PORT`: Server port (default: 3000)
   - `BCRYPT_SALT_ROUNDS`: Password hashing rounds (default: 12)

3. **Initialize the database:**
   ```bash
   npm run init-db
   ```

4. **Start the application:**
   ```bash
   npm start
   ```

5. **Verify it's working:**
   ```bash
   curl http://localhost:3000/health
   ```

## What's Included

- **Large Monolithic Controller** (`controllers/userController.js`) - 800+ lines handling multiple responsibilities
- **Database Setup** - SQLite database with user, order, and analytics tables
- **Complete API** - Registration, login, orders, profile updates, analytics
- **Workshop Guide** - Step-by-step refactoring instructions in `WORKSHOP_GUIDE.md`
- **Simplified Dependencies** - Express, SQLite, JWT, Bcrypt with mock email and payment services (no external dependencies)

## Design Decisions

This workshop uses **mock services** for email and payment processing to avoid complex external dependencies while maintaining educational value:

- **Mock Email Service** - Simulates email sending without requiring SMTP configuration
- **Mock Payment Service** - Demonstrates payment processing patterns without external payment providers
- **All Core Functionality** - Registration, authentication, orders, and notifications work without internet connectivity

This approach lets you focus on **refactoring patterns** and **GitHub Copilot usage** without getting bogged down by external service configuration.

## Security Configuration

**Important:** The application uses environment variables for sensitive configuration:

- **JWT_SECRET**: Used for signing JWT tokens. In production, use a strong, unique secret key
- **BCRYPT_SALT_ROUNDS**: Controls password hashing strength (default: 12)
- **Never commit your `.env` file** - it's excluded by `.gitignore`
- Use `.env.example` as a template for required environment variables

## The Workshop Journey

Follow `WORKSHOP_GUIDE.md` to learn how to:
1. Extract an AuthService from authentication logic
2. Create an EmailService for notifications  
3. Build a PaymentService for payment processing
4. Develop an OrderService for order management
5. Implement an AnalyticsService for tracking
6. Create a UserProfileService for profile management
7. Refactor the controller to use all services

Each step includes GitHub Copilot prompts and complete solutions.