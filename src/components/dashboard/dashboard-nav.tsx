"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const navigation = [
  { href: "/dashboard", code: "00", label: "Overview" },
  { href: "/dashboard/campaigns", code: "01", label: "Campaigns" },
  { href: "/dashboard/inboxes", code: "02", label: "Inboxes" },
  { href: "/dashboard/consent", code: "03", label: "Consent" },
  { href: "/dashboard/suppressions", code: "04", label: "Suppressions" },
] as const;

export function DashboardNav() {
  const pathname = usePathname();

  return (
    <nav className="vault-nav" aria-label="Primary navigation">
      {navigation.map((item) => {
        const active =
          item.href === "/dashboard"
            ? pathname === item.href
            : pathname.startsWith(item.href);
        return (
          <Link
            href={item.href}
            key={item.href}
            aria-current={active ? "page" : undefined}
            className={active ? "nav-link nav-link-active" : "nav-link"}
          >
            <span>{item.code}</span>
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}
