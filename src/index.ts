import fastify from 'fastify';
import { connectMongoDB, disconnectMongoDB } from './infra/database/database';
import { defineEndpoints } from './infra/api';
import { defineSecurity } from './infra/api';
import { logger } from './infra/logger';
import { registerRequestLogger } from './infra/interceptors/request-logger';
import { port, rpName } from './setup';
import { connectRedis, disconnectRedis } from './infra/database/redis';

const server = fastify({
    logger: false // Disable Fastify's built-in logger
});

defineSecurity(server);
defineEndpoints(server);
registerRequestLogger(server);

const start = async () => {
    try {
        // Connect to MongoDB
        await connectMongoDB();

        await connectRedis();

        await server.listen({ port: Number(port), host: '0.0.0.0' });
        logger.info(`Server ${rpName} is running on port ${port}`);
    } catch (err) {
        logger.error('Server failed to start:', err);
        process.exit(1);
    }
};

// Handle graceful shutdown
process.on('SIGINT', async () => {
    logger.info('SIGINT received');
    await disconnectMongoDB();
    await disconnectRedis();
    process.exit(0);
});

process.on('SIGTERM', async () => {
    logger.info('SIGTERM received');
    await disconnectMongoDB();
    await disconnectRedis();
    process.exit(0);
});

start();

