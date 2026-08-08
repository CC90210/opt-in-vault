import { render, screen } from "@testing-library/react";

import { LoginForm } from "./login-form";

describe("login form", () => {
  it("uses a password field, does not retain the key, and explains the exchange", () => {
    render(<LoginForm />);

    const key = screen.getByLabelText(/tenant api key/i);
    expect(key).toHaveAttribute("type", "password");
    expect(key).toHaveAttribute("name", "apiKey");
    expect(key).toHaveAttribute("autocomplete", "off");
    expect(screen.getByRole("button", { name: /open private vault/i })).toBeVisible();
    expect(screen.getByText(/short-lived, http-only session/i)).toBeVisible();
  });

  it("announces authentication errors without echoing credentials", () => {
    render(<LoginForm error="invalid" />);

    const alert = screen.getByRole("alert");
    const key = screen.getByLabelText(/tenant api key/i);

    expect(alert).toHaveTextContent(/could not be verified/i);
    expect(screen.getByRole("alert")).not.toHaveTextContent("oiv_sk_");
    expect(key).toHaveAttribute("aria-invalid", "true");
    expect(key).toHaveAttribute("aria-describedby", "api-key-help api-key-error");
    expect(alert).toHaveAttribute("id", "api-key-error");
  });

  it("bounds and disables mobile transformations for the fixed-format key", () => {
    render(<LoginForm />);

    const key = screen.getByLabelText(/tenant api key/i);
    expect(key).toHaveAttribute("maxlength", "50");
    expect(key).toHaveAttribute("autocapitalize", "none");
  });
});
