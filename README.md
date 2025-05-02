# Passkeys Server

A Fastify-based server implementation for WebAuthn/Passkeys authentication. This server provides endpoints for user registration and authentication using modern passwordless authentication methods.

## Features

- WebAuthn/Passkeys registration and authentication
- MongoDB for user storage
- Redis for challenge management
- Winston logging system
- Request logging interceptor
- TypeScript support
- Environment-based configuration

## Prerequisites

- Node.js (v16 or higher)
- MongoDB
- Redis
- npm or yarn

## Installation

1. Clone the repository:
```bash
git clone https://github.com/renatodecampos/passkeys-server.git
cd passkeys-server
```

2. Install dependencies:
```bash
npm install
```

3. Create a `.env` file:
```bash
cp .env.example .env
```

4. Update the `.env` file with your configuration:
- Set your MongoDB credentials
- Configure Redis connection
- Set your WebAuthn relying party details
- Configure session and logging settings

## Environment Variables

- `PORT`: Server port (default: 3000)
- `HOST`: Server host (default: 0.0.0.0)
- `MONGODB_URI`: MongoDB connection string
- `MONGODB_DATABASE`: MongoDB database name
- `REDIS_HOST`: Redis host
- `REDIS_PORT`: Redis port
- `REDIS_PASSWORD`: Redis password
- `RP_ID`: WebAuthn relying party ID
- `RP_NAME`: WebAuthn relying party name
- `RP_ORIGIN`: WebAuthn relying party origin
- `SESSION_SECRET`: Session secret key
- `SESSION_TTL`: Session time-to-live in seconds
- `LOG_LEVEL`: Logging level (error, warn, info, debug)
- `REGISTRATION_TIMEOUT`: Registration timeout in milliseconds

## API Endpoints

### Registration

- `POST /generate-registration-options`
  - Request body: `{ username: string }`
  - Returns registration options for WebAuthn

- `POST /verify-registration`
  - Request body: Registration response from authenticator
  - Verifies and stores the new credential

### Authentication

- `POST /generate-authentication-options`
  - Request body: `{ username: string }`
  - Returns authentication options for WebAuthn

- `POST /verify-authentication`
  - Request body: Authentication response from authenticator
  - Verifies the authentication attempt

## Development

1. Start the development server:
```bash
npm run dev
```

2. Run tests:
```bash
npm test
```

3. Build for production:
```bash
npm run build
```

## Logging

The server uses Winston for logging with the following features:
- Console output with colors
- File-based logging in `logs/` directory
- Separate error logs
- Request logging with timing information
- Configurable log levels

## Security Considerations

- Always use HTTPS in production
- Keep your session secret secure
- Regularly rotate credentials
- Monitor logs for suspicious activity
- Keep dependencies updated

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
