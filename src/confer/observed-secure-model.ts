/**
 * Shapes observed inside the browser's encrypted protobuf WebSocket transport.
 * These TypeScript types document the JSON layer only; the outer protobuf,
 * framing, Noise session, and TDX attestation validation still need a faithful
 * implementation from the extracted source modules.
 */

export const OBSERVED_TEE_WEBSOCKET_URL = 'wss://inference.confer.to/websocket';
export const OBSERVED_NOISE_PROTOCOL = 'Noise_XX_25519_AESGCM_SHA256';
export const OBSERVED_CHAT_PATH = '/v1/vllm/chat/completions';

export interface ObservedChatMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string;
}

export interface ObservedStreamEvent {
  type: 'token' | 'thinking' | 'tool_call' | 'tool_response' | 'client_tool_call' | 'completion';
  content?: string;
}

export interface NoiseWebsocketRequest {
  id: bigint;
  verb: string;
  path: string;
  body?: Uint8Array;
}
