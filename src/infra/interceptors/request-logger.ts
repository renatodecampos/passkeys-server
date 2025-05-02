import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { logger } from '../logger';

interface CustomFastifyRequest extends FastifyRequest {
    startTime?: number;
}

export const registerRequestLogger = (server: FastifyInstance) => {
    // Log request start
    server.addHook('onRequest', async (request: CustomFastifyRequest) => {
        const startTime = Date.now();
        request.startTime = startTime;
        
        logger.info('Incoming request', {
            method: request.method,
            url: request.url,
            headers: request.headers,
            query: request.query,
            body: request.body,
            ip: request.ip
        });
    });

    // Log response
    server.addHook('onResponse', async (request: CustomFastifyRequest, reply: FastifyReply) => {
        const responseTime = Date.now() - (request.startTime || Date.now());
        
        logger.info('Request completed', {
            method: request.method,
            url: request.url,
            statusCode: reply.statusCode,
            responseTime: `${responseTime}ms`
        });
    });

    // Log errors
    server.addHook('onError', async (request: FastifyRequest, reply: FastifyReply, error: Error) => {
        logger.error('Request error', {
            method: request.method,
            url: request.url,
            error: {
                message: error.message,
                stack: error.stack
            }
        });
    });
}; 