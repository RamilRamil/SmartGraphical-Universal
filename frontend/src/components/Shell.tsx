import type { ReactNode } from "react";

import { HealthBadge } from "./HealthBadge";
import { Nav } from "./Nav";

type ShellProps = {
  children: ReactNode;
};

export function Shell({ children }: ShellProps) {
  return (
    <div className="sg-shell">
      <aside className="sg-shell__sidebar">
        <div className="sg-shell__brand">SmartGraphical</div>
        <Nav />
        <div className="sg-shell__status">
          <HealthBadge />
        </div>
      </aside>
      <main className="sg-shell__main">{children}</main>
    </div>
  );
}
