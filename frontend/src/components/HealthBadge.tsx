import { useHealth } from "../api/hooks";

export function HealthBadge() {
  const query = useHealth();
  if (query.isLoading) {
    return <span className="sg-health sg-health--pending">checking...</span>;
  }
  if (query.isError || query.data?.status !== "ok") {
    return <span className="sg-health sg-health--error">backend offline</span>;
  }
  return <span className="sg-health sg-health--ok">backend ok</span>;
}
