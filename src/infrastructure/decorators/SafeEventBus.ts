import { DomainEvent, DomainEventType } from "../../core/domain/events";
import { EventHandler, IEventBus, ILogger } from "../../core/ports/services";

/**
 * Decorator: wraps ANY IEventBus (even a custom Kafka/Redis one) so publishing can never
 * make a login or authorization call fail. Audit trouble must not become an outage.
 */
export class SafeEventBus implements IEventBus {
  constructor(private readonly inner: IEventBus, private readonly logger: ILogger) {}
  async publish(event: DomainEvent): Promise<void> {
    try { await this.inner.publish(event); }
    catch (err) { this.logger.error(`Event publish failed for ${event.type}`, { err: String(err) }); }
  }
  subscribe(type: DomainEventType | "*", handler: EventHandler): () => void {
    return this.inner.subscribe(type, handler);
  }
}
