import { NavLink } from "react-router-dom";

const LINKS: Array<{ to: string; label: string }> = [
  { to: "/upload", label: "Upload" },
  { to: "/history", label: "History" },
];

export function Nav() {
  return (
    <nav className="sg-nav">
      {LINKS.map((link) => (
        <NavLink
          key={link.to}
          to={link.to}
          className={({ isActive }) =>
            isActive ? "sg-nav__link sg-nav__link--active" : "sg-nav__link"
          }
        >
          {link.label}
        </NavLink>
      ))}
    </nav>
  );
}
