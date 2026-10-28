import { ConfigError, ResourceNotFoundError } from "../core/domain/errors";

export type ResourceLoader = (id: string) => Promise<unknown | null | undefined> | unknown | null | undefined;

/** The host teaches the library how to fetch a resource, so policies can check ownership/attributes. */
export class ResourceLoaderRegistry {
  private readonly loaders = new Map<string, ResourceLoader>();

  register(type: string, loader: ResourceLoader): this {
    if (this.loaders.has(type)) throw new ConfigError(`Resource loader "${type}" is already registered`);
    this.loaders.set(type, loader);
    return this;
  }

  async load(type: string, id: string): Promise<unknown> {
    const loader = this.loaders.get(type);
    if (!loader) throw new ConfigError(`No resource loader registered for type "${type}"`);
    const data = await loader(id);
    if (data === null || data === undefined) throw new ResourceNotFoundError(`${type} not found`);
    return data;
  }
}
