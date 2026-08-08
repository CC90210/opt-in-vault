type LoginFormProps = {
  error?: string;
};

const errorMessages: Record<string, string> = {
  invalid: "That API key could not be verified for dashboard access.",
  configuration: "The private vault is not configured for sign-in yet.",
};

export function LoginForm({ error }: LoginFormProps) {
  const message = error ? errorMessages[error] ?? errorMessages.invalid : null;

  return (
    <form className="login-form" method="post" action="/api/auth/login">
      {message ? (
        <div className="form-alert" id="api-key-error" role="alert">
          <span aria-hidden="true">!</span>
          <p>{message}</p>
        </div>
      ) : null}

      <div className="field-stack">
        <label htmlFor="api-key">Tenant API key</label>
        <input
          id="api-key"
          name="apiKey"
          type="password"
          autoComplete="off"
          spellCheck={false}
          inputMode="text"
          autoCapitalize="none"
          maxLength={50}
          required
          pattern="oiv_sk_[A-Za-z0-9_-]{43}"
          placeholder="oiv_sk_••••••••••••••••"
          aria-describedby={message ? "api-key-help api-key-error" : "api-key-help"}
          aria-invalid={message ? true : undefined}
        />
        <p id="api-key-help" className="field-help">
          Your key is exchanged once for a short-lived, HTTP-only session. It
          is never written to browser storage.
        </p>
      </div>

      <button className="primary-action" type="submit">
        <span>Open private vault</span>
        <span aria-hidden="true">↗</span>
      </button>
    </form>
  );
}
