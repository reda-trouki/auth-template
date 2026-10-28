interface Base { readonly occurredAt: Date }

export type DomainEvent =
  | (Base & { type: "UserRegistered"; userId: string })
  | (Base & { type: "LoginSucceeded"; userId: string; ip?: string; userAgent?: string })
  | (Base & {
      type: "LoginFailed";
      userId?: string;
      reason: "unknown_user" | "bad_password" | "locked" | "suspended";
      ip?: string;
      userAgent?: string;
    })
  | (Base & { type: "AccountLocked"; userId: string; until: Date })
  | (Base & { type: "RefreshTokenReuseDetected"; userId: string; familyId: string })
  | (Base & { type: "PasswordChanged"; userId: string })
  | (Base & { type: "LoggedOut"; userId: string; familyId?: string })
  | (Base & {
      type: "AuthorizationDecided";
      subjectId: string;
      action: string;
      effect: "allow" | "deny";
      reason?: string;
      resourceType?: string;
      resourceId?: string;
    });

export type DomainEventType = DomainEvent["type"];
