import { DomainEvent, DomainEventType } from "../../core/domain/events";
import { EventHandler, IEventBus, ILogger } from "../../core/ports/services";

export class InMemoryEventBus implements IEventBus {
  private readonly handlers = new Map<DomainEventType | "*", Set<EventHandler>>();
  constructor(private readonly logger: ILogger) {}

  subscribe(type: DomainEventType | "*", handler: EventHandler): () => void {
    const set = this.handlers.get(type) ?? new Set<EventHandler>();
    set.add(handler);
    this.handlers.set(type, set);
    return () => { set.delete(handler); };
  }

  /** Subscribers are isolated: one throwing handler never affects others or the publisher. */
  async publish(event: DomainEvent): Promise<void> {
    const targets = [...(this.handlers.get(event.type) ?? []), ...(this.handlers.get("*") ?? [])];
    const results = await Promise.allSettled(targets.map(async (h) => h(event)));
    for (const r of results) {
      if (r.status === "rejected") this.logger.error(`Event handler failed for ${event.type}`, { err: String(r.reason) });
    }
  }
}
