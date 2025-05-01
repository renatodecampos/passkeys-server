import fastify from 'fastify';
import helmet from '@fastify/helmet';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import secureSession from '@fastify/secure-session';
import crypto from 'crypto';
import { getRegistrationOptions, verifyRegistration } from './registration';
import { RegistrationResponseJSON } from '@simplewebauthn/server';

declare module '@fastify/secure-session' {
    interface SessionData {
        currentChallenge?: string;
    }
}

// Generate a secure 32-byte session key
const generateSessionKey = () => {
    return crypto.randomBytes(32).toString('hex');
};

// Use environment variable or generate a new key
const SESSION_KEY = process.env.SESSION_KEY || generateSessionKey();

const server = fastify({
    logger: true,
    trustProxy: true, // Enable if behind a proxy
});

// Register security plugins
server.register(helmet, {
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'"],
            imgSrc: ["'self'"],
            connectSrc: ["'self'"],
        },
    },
});

server.register(cors, {
    origin: process.env.NODE_ENV === 'production'
        ? ['https://yourdomain.com'] // Replace with your actual domain
        : ['http://localhost:3000'],
    credentials: true,
});


const rateLimitConfig = {
    max: Number(process.env.RATE_LIMIT_MAX) || 100,
    timeWindow: process.env.RATE_LIMIT_TIME_WINDOW || '1 minute',
};

server.register(rateLimit, rateLimitConfig);

server.register(secureSession, {
    key: Buffer.from(SESSION_KEY, 'hex'),
    sessionName: 'session',
    cookieName: 'my-session-cookie',
    expiry: 24 * 60 * 60, // Default 1 day
    cookie: {
        path: '/',
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
    },
});

// Health check route
server.get('/health', async () => {
    return { status: 'ok' };
});

/**
 * Get Registration Options (a.k.a. "Get Registration Options")
 * When you register a new user, you need to create a credential to eventually authenticate. 
 * Credential registration is a WebAuthn ceremony, where a User (you) interacts with a Client (your web browser) 
 * to create a public key credential (your passkey) on an Authenticator (such as a security key, Google Password Manager, or iCloud Keychain).
 * This new credential is scoped to a specific Relying Party (a web application), 
 * which means that the User can only use the credential on the domain of that web application. 
 * The Relying Party also associates the credential with the User's account.
 */
server.get('/generate-registration-options', async (request, reply) => {
    try {
        const userId = request.headers['x-user-id'] as string || '75f45645-fec7-45f4-84bf-73eb31538550';
        const registrationOptions = await getRegistrationOptions(userId);

        if (!registrationOptions) {
            reply.status(404).send({ error: 'User not found' });
            return;
        }

        (request.session as any).set('currentChallenge', registrationOptions.challenge);

        reply.status(200).send(registrationOptions);
    } catch (error) {
        const _error = error as Error;
        reply.status(500).send({ error: _error.message });
    }
});

/**
 * Verify Registration (a.k.a. "Verify Registration")
 * The Relying Party Server needs to verify the attestation response by checking its signed challenge 
 * to confirm that a legitimate device created the credential.
 */
server.post('/verify-registration', async (request, reply) => {
    try {
        const userId = request.headers['x-user-id'] as string || '75f45645-fec7-45f4-84bf-73eb31538550';
        const expectedChallenge = (request.session as any).get('currentChallenge');
        if (!expectedChallenge) {
            throw new Error('No challenge found');
        }
        const registrationResponse = request.body as RegistrationResponseJSON;
        const verified = await verifyRegistration(userId, expectedChallenge, registrationResponse);

        reply.status(200).send({ verified });
    } catch (error) {
        const _error = error as Error;
        reply.status(500).send({ error: _error.message });
    }
});

/**
 * Login (a.k.a. "Authentication")
 */
server.get('/generate-authentication-options', async (request, reply) => {
    throw new Error('Not implemented');
});

/**
 * Verify Authentication (a.k.a. "Verify Authentication")
 */
server.post('/verify-authentication', async (request, reply) => {
    throw new Error('Not implemented');
});





// Error handler
server.setErrorHandler((error, request, reply) => {
    server.log.error(error);
    if (error.statusCode === 429) {
        reply.code(429)
        error.message = 'You hit the rate limit! Slow down please!'
    }
    reply.status(error.statusCode || 500).send({
        error: {
            message: error.message,
            code: error.code,
        },
    });
});

const start = async () => {
    try {
        const port = process.env.PORT || 3000;
        await server.listen({ port: Number(port), host: '0.0.0.0' });
        console.log(`Server is running on port ${port}`);
        console.log(`Session key: ${SESSION_KEY}`);
    } catch (err) {
        server.log.error(err);
        process.exit(1);
    }
};

start();

