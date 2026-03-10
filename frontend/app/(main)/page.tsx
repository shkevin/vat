import { getAppConfig } from "@/config/app";
import VAT from "@/components/VAT";

export default function HomePage() {
  const config = getAppConfig();
  return <VAT config={config} />;
}
