import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import helmet from '@fastify/helmet';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import fastifySession from '@fastify/session';
import fastifyCookie from '@fastify/cookie';
import { getRegistrationOptions, verifyRegistration } from "../../registration";
import { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";
import { getAuthenticationOptions, verifyAuthentication } from "../../authentication";
import { redis } from "../database/redis";
import crypto from 'crypto';
import { sessionKey, rateLimitMax, rateLimitTimeWindow, environment } from "../../setup";

// Define session interface
declare module '@fastify/session' {
    interface Session {
        currentChallenge?: string;
    }
}

// Generate a secure 32-byte session key
const generateSessionKey = () => {
    return crypto.randomBytes(32).toString('hex');
};

// Define endpoints
export const defineEndpoints = (server: FastifyInstance) => {
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
    server.post('/generate-registration-options', async (request: FastifyRequest, reply: FastifyReply) => {
        try {
            const { username } = request.body as { username: string };
            const registrationOptions = await getRegistrationOptions(username);

            if (!registrationOptions) {
                reply.status(404).send({ error: 'User not found' });
                return;
            }

            reply.send(registrationOptions);
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
    server.post('/verify-registration', async (request: FastifyRequest, reply: FastifyReply) => {
        try {
            const username = request.headers['x-username'] as string;

            if (!username) {
                throw new Error('Username is required in the header x-username');
            }

            const registrationResponse = request.body as RegistrationResponseJSON;
            const verified = await verifyRegistration(username, registrationResponse);

            reply.send({ verified });
        } catch (error) {
            const _error = error as Error;
            reply.status(500).send({ error: _error.message });
        }
    });

    /**
     * Login (a.k.a. "Authentication")
     */
    server.post('/generate-authentication-options', async (request: FastifyRequest, reply: FastifyReply) => {
        try {
            const username = request.headers['x-username'] as string;

            if (!username) {
                throw new Error('Username is required in the header x-username');
            }

            const authenticationOptions = await getAuthenticationOptions(username);

            if (!authenticationOptions) {
                reply.status(404).send({ error: 'User not found' });
                return;
            }

            reply.send(authenticationOptions);
        } catch (error) {
            const _error = error as Error;
            reply.status(500).send({ error: _error.message });
        }
    });

    /**
     * Verify Authentication (a.k.a. "Verify Authentication")
     */
    server.post('/verify-authentication', async (request: FastifyRequest, reply: FastifyReply) => {
        try {
            const username = request.headers['x-username'] as string;

            if (!username) {
                throw new Error('Username is required in the header x-username');
            }

            const authenticationResponse = request.body as AuthenticationResponseJSON;
            const verified = await verifyAuthentication(username, authenticationResponse);

            // Delete the challenge after use
            await redis.del(`challenge:${username}-authentication`);

            reply.send({ verified });
        } catch (error) {
            const _error = error as Error;
            reply.status(500).send({ error: _error.message });
        }
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
}

// Define security plugins
export const defineSecurity = (server: FastifyInstance) => {
    server.register(fastifyCookie);

    const SESSION_KEY = sessionKey || generateSessionKey();

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
        origin: environment === 'production'
            ? ['https://yourdomain.com'] // Replace with your actual domain
            : ['http://localhost:3000', 'http://localhost:3001'],
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['*'],
    });


    const rateLimitConfig = {
        max: Number(rateLimitMax) || 100,
        timeWindow: rateLimitTimeWindow || '1 minute',
    };

    server.register(rateLimit, rateLimitConfig);

    server.register(fastifySession, {
        secret: SESSION_KEY,
        cookieName: 'sessionId',
        cookie: {
            maxAge: 1800000,
            secure: environment === 'production',
        },
    });
}