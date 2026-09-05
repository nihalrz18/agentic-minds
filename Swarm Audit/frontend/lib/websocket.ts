export interface AgentMessage {
  agent_name: string;
  agent_type: string;
  status: 'thinking' | 'working' | 'done' | 'error';
  message: string;
  data?: Record<string, unknown> | null;
  timestamp: number;
}

type MessageHandler    = (event: AgentMessage) => void;
type StatusHandler     = (status: ConnectionStatus) => void;
type ConnectionStatus  = 'connecting' | 'connected' | 'disconnected' | 'error';

export class WebSocketManager {
  private ws:              WebSocket | null = null;
  private sessionId:       string;
  private githubUrl:       string;
  private messageHandlers: MessageHandler[] = [];
  private statusHandlers:  StatusHandler[]  = [];
  private retryCount       = 0;
  private maxRetries       = 3;
  private retryTimer:      ReturnType<typeof setTimeout> | null = null;
  private manualClose      = false;

  constructor(sessionId: string, githubUrl: string) {
    this.sessionId  = sessionId;
    this.githubUrl  = githubUrl;
    this.connect();
  }

  private connect(): void {
    const wsBase = process.env.NEXT_PUBLIC_WS_URL ?? 'ws://localhost:8000';
    const url    = `${wsBase}/ws/audit/${this.sessionId}`;

    this.emitStatus('connecting');

    try {
      this.ws = new WebSocket(url);
    } catch {
      this.emitStatus('error');
      return;
    }

    this.ws.onopen = () => {
      this.retryCount = 0;
      this.emitStatus('connected');
      // Send github_url immediately after connecting
      this.ws?.send(JSON.stringify({ github_url: this.githubUrl }));
    };

    this.ws.onmessage = (event: MessageEvent) => {
      try {
        const msg = JSON.parse(event.data as string) as AgentMessage;
        this.messageHandlers.forEach(h => h(msg));
      } catch {
        // Ignore malformed messages
      }
    };

    this.ws.onerror = () => {
      this.emitStatus('error');
    };

    this.ws.onclose = () => {
      if (this.manualClose) {
        this.emitStatus('disconnected');
        return;
      }
      if (this.retryCount < this.maxRetries) {
        const delay = Math.pow(2, this.retryCount) * 1000; // 1s, 2s, 4s
        this.retryCount++;
        this.emitStatus('connecting');
        this.retryTimer = setTimeout(() => this.connect(), delay);
      } else {
        this.emitStatus('disconnected');
      }
    };
  }

  onMessage(handler: MessageHandler): void {
    this.messageHandlers.push(handler);
  }

  onStatusChange(handler: StatusHandler): void {
    this.statusHandlers.push(handler);
  }

  disconnect(): void {
    this.manualClose = true;
    if (this.retryTimer) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  private emitStatus(status: ConnectionStatus): void {
    this.statusHandlers.forEach(h => h(status));
  }
}
