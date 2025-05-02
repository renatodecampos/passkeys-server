import { MongoClient, Db, Collection } from 'mongodb';
import { WebAuthnCredential } from '@simplewebauthn/server';
import { UserModel } from '../../types';
import { logger } from '../logger';
import { collectionName, mongodbUri } from '../../setup';


let client: MongoClient;
let db: Db;

export const connectMongoDB = async (): Promise<void> => {
    try {
        client = new MongoClient(mongodbUri);
        await client.connect();
        db = client.db();
        logger.info('Connected to MongoDB');
    } catch (error) {
        logger.error('MongoDB connection error:', error);
        throw error;
    }
};

export const disconnectMongoDB = async (): Promise<void> => {
    try {
        await client.close();
        logger.info('Disconnected from MongoDB');
    } catch (error) {
        logger.error('MongoDB disconnection error:', error);
        throw error;
    }
};

const getCollection = (): Collection<UserModel> => {
    return db.collection<UserModel>(collectionName);
};

export const getUser = async (username: string): Promise<UserModel | null> => {
    try {
        const collection = getCollection();
        return await collection.findOne({ username: username });
    } catch (error) {
        logger.error('Error getting user:', error);
        throw error;
    }
};

export const createUser = async (user: UserModel): Promise<void> => {
    try {
        const collection = getCollection();
        await collection.insertOne(user);
    } catch (error) {
        logger.error('Error creating user:', error);
        throw error;
    }
};

export const updateUser = async (userId: string, user: Partial<UserModel>): Promise<void> => {
    try {
        const collection = getCollection();
        await collection.updateOne(
            { id: userId },
            { $set: user }
        );
    } catch (error) {
        logger.error('Error updating user:', error);
        throw error;
    }
};

export const addCredential = async (userId: string, credential: WebAuthnCredential): Promise<void> => {
    try {
        const collection = getCollection();
        await collection.updateOne(
            { id: userId },
            { $push: { credentials: credential } }
        );
    } catch (error) {
        logger.error('Error adding credential:', error);
        throw error;
    }
}; 