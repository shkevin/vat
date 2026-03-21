import { Suspense } from "react";
import { getAppConfig } from "@/config/app";
import { AssetPage } from "@/components/assets/AssetPage";

export default function AssetRoutePage() {
  const config = getAppConfig();
  return (
    <Suspense
      fallback={
        <div className="flex items-center justify-center p-8">
          Loading asset...
        </div>
      }
    >
      <AssetPage config={config} />
    </Suspense>
  );
}
