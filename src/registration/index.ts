import { generateRegistrationOptions, GenerateRegistrationOptionsOpts, RegistrationResponseJSON, verifyAuthenticationResponse, VerifyAuthenticationResponseOpts, verifyRegistrationResponse, WebAuthnCredential } from "@simplewebauthn/server";
import { LoggedInUser } from "../types";
import { FastifyRequest } from "fastify";

/**
 * 2FA and Passwordless WebAuthn flows expect you to be able to uniquely identify the user that
 * performs registration or authentication. The user ID you specify here should be your internal,
 * _unique_ ID for that user (uuid, etc...). Avoid using identifying information here, like email
 * addresses, as it may be stored within the credential.
 *
 * Here, the example server assumes the following user has completed login:
 */
const loggedInUserId = '75f45645-fec7-45f4-84bf-73eb31538550'; // TODO: Replace with actual user ID
const rpID = 'localhost'; // TODO: Replace with actual RP ID
const loggedInUserDisplayName = 'John Doe';
const rpName = 'WebAuthn Example'; // TODO: Replace with actual RP Name

const inMemoryUserDB: { [loggedInUserId: string]: LoggedInUser } = {
    [loggedInUserId]: {
        id: loggedInUserId,
        username: `user@${rpID}`,
        credentials: [],
    },
};

/**
 * Get Registration Options
 * @param userId - The user ID of the logged in user
 * @returns The registration options for the user
 */
export const getRegistrationOptions = async (userId: string) => {
    const user = inMemoryUserDB[userId];
    if (!user) {
        throw new Error('User not found');
    }

    const {
        /**
         * The username can be a human-readable name, email, etc... as it is intended only for display.
         */
        username,
        credentials,
    } = user;

    const options: GenerateRegistrationOptionsOpts = {
        rpName,
        rpID,
        userName: username,
        userID: new TextEncoder().encode(userId),
        userDisplayName: loggedInUserDisplayName,
        timeout: Number(process.env.REGISTRATION_TIMEOUT) || 60000,
        attestationType: 'none',
        /**
         * Passing in a user's list of already-registered credential IDs here prevents users from
         * registering the same authenticator multiple times. The authenticator will simply throw an
         * error in the browser if it's asked to perform registration when it recognizes one of the
         * credential ID's.
         */
        excludeCredentials: credentials.map((cred) => ({
            id: cred.id,
            type: 'public-key',
            transports: cred.transports,
        })),
        authenticatorSelection: {
            residentKey: 'discouraged',
            userVerification: 'preferred',
        },
        /**
         * Support the two most common algorithms: ES256, and RS256
         */
        supportedAlgorithmIDs: [-7, -257],
    };

    const registrationOptions = await generateRegistrationOptions(options);

    return registrationOptions;
};


/**
 * Verify Registration
 * @param userId - The user ID of the logged in user
 * @param expectedChallenge - The expected challenge
 * @param registrationResponse - The registration response
 * @returns The verified registration response
 */
export const verifyRegistration = async (userId: string, expectedChallenge: string, registrationResponse: RegistrationResponseJSON) => {
    const user = inMemoryUserDB[userId];
    if (!user) {
        throw new Error('User not found');
    }

    // Find existing credential by ID
    const existingCredential = user.credentials.find(
        (cred: WebAuthnCredential) => cred.id === registrationResponse.id
    );

    if (existingCredential) {
        throw new Error('Authenticator is already registered with this site');
    }

    try {
        const verification = await verifyRegistrationResponse({
            response: registrationResponse,
            expectedChallenge: `${expectedChallenge}`,
            expectedOrigin: `http://${rpID}`,
            expectedRPID: rpID,
            requireUserVerification: false,
        });

        const { verified, registrationInfo } = verification;

        if (verified && existingCredential && registrationInfo?.credential) {
            // Update the credential's counter in the DB to the newest count in the authentication
            const credential = existingCredential as WebAuthnCredential;
            credential.counter = registrationInfo.credential.counter;
        }

        return verified;
    } catch (error) {
        const _error = error as Error;
        console.error(_error);
        throw _error;
    }
};
