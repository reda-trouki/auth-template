import { InMemorySessionRepository, InMemoryUserRepository } from "../../src";
import { runSessionRepositoryContract, runUserRepositoryContract } from "./repositories.contract";

runUserRepositoryContract("in-memory", () => new InMemoryUserRepository());
runSessionRepositoryContract("in-memory", () => new InMemorySessionRepository());
