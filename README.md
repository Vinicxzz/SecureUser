# User Authentication API

This is a simple user authentication API built with Node.js, Express, MongoDB, and JWT for token-based authentication. It allows users to register, login, and access a protected route that requires a valid token.

## Features

- User registration with hashed passwords
- User login with JWT token generation
- Protected route accessible only with a valid JWT token
- Error handling for common issues such as invalid credentials or missing fields

## Technologies Used

- Node.js
- Express
- MongoDB with Mongoose
- Bcrypt for password hashing
- JWT (jsonwebtoken) for token-based authentication
- dotenv for environment variables

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/your-username/your-repo-name.git
