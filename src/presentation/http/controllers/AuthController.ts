import type { Request, Response } from "express";
import { z } from "zod";
import { UnauthenticatedError } from "../../../core/domain/errors";
import { AuthResult } from "../../../core/domain/entities";
import { ChangePassword } from "../../../core/use-cases/ChangePassword";
import { LoginUser } from "../../../core/use-cases/LoginUser";
import { LogoutUser } from "../../../core/use-cases/LogoutUser";
import { RefreshSession } from "../../../core/use-cases/RefreshSession";
import { RegisterUser } from "../../../core/use-cases/RegisterUser";
import { IUserRepository } from "../../../core/ports/repositories";
import { toPublicUser } from "../../../core/domain/entities";
import { changePasswordSchema, loginSchema, refreshSchema, registerSchema } from "../dto/schemas";

const present = (r: AuthResult) => ({ user: r.user, tokens: r.tokens });
const parse = <T extends z.ZodTypeAny>(schema: T, body: unknown): z.infer<T> => schema.parse(body ?? {});

/** Thin translator: HTTP in -> use case -> HTTP out. No business rules here. */
export class AuthController {
  constructor(
    private readonly registerUser: RegisterUser,
    private readonly loginUser: LoginUser,
    private readonly refreshSession: RefreshSession,
    private readonly logoutUser: LogoutUser,
    private readonly changePassword: ChangePassword,
    private readonly users: IUserRepository,
  ) {}

  register = async (req: Request, res: Response) => {
    const { email, password } = parse(registerSchema, req.body); // roles are never read from the client
    res.status(201).json({ user: await this.registerUser.execute({ email, password }) });
  };

  login = async (req: Request, res: Response) => {
    const { email, password } = parse(loginSchema, req.body);
    const result = await this.loginUser.execute({ email, password, ip: req.ip, userAgent: req.get("user-agent") });
    res.status(200).json(present(result));
  };

  refresh = async (req: Request, res: Response) => {
    res.status(200).json(present(await this.refreshSession.execute(parse(refreshSchema, req.body))));
  };

  logout = async (req: Request, res: Response) => {
    await this.logoutUser.execute(parse(refreshSchema, req.body));
    res.status(204).end();
  };

  logoutAll = async (req: Request, res: Response) => {
    if (!req.auth) throw new UnauthenticatedError();
    await this.logoutUser.executeAll({ userId: req.auth.subject.id });
    res.status(204).end();
  };

  changePasswordHandler = async (req: Request, res: Response) => {
    if (!req.auth) throw new UnauthenticatedError();
    const body = parse(changePasswordSchema, req.body);
    await this.changePassword.execute({ userId: req.auth.subject.id, ...body });
    res.status(204).end();
  };

  me = async (req: Request, res: Response) => {
    if (!req.auth) throw new UnauthenticatedError();
    const user = await this.users.findById(req.auth.subject.id);
    if (!user) throw new UnauthenticatedError(); // account deleted after token issue
    res.status(200).json({ user: toPublicUser(user) });
  };
}
