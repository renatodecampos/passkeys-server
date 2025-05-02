import Redis from 'ioredis';
import { redisUrl } from '../../setup';
import { logger } from '../logger';
export let redis: Redis;

export const connectRedis = async (): Promise<void> => {
    redis = new Redis(redisUrl);

    redis.on('error', (err) => {
        logger.error('Redis error:', err);
    });

    redis.on('connect', () => {
        logger.info('Redis connected');
    });

    redis.on('close', () => {
        logger.info('Redis closed');
    });
};

export const disconnectRedis = async (): Promise<void> => {
    redis.disconnect();
};

