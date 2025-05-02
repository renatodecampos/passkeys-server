import { WebAuthnCredential } from "@simplewebauthn/server";

export type UserModel = {
    id: string;
    username: string;
    displayName: string;
    credentials: WebAuthnCredential[];
};