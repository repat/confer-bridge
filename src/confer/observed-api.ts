/** Shapes observed in the supplied HAR. These are not a complete confer.to SDK. */

export interface EncryptedChatRecord {
  id: string;
  ciphertext: string;
  encryptedKey: string;
  createdAt: string;
  lastMessageAt: string | null;
}

export interface EncryptedMessageRecord {
  messageId: string;
  ciphertext: string;
  createdAt: string;
}

export interface CreateChatRequest {
  ciphertext: string;
  encryptedKey: string;
}

export interface StoreMessageRequest {
  ciphertext: string;
}

export interface ModelTokenResponse {
  token: string;
}
