import { getAppConfig } from "@/config/app";
import { AuthGuard } from "@/components/AuthGuard";
import { MainAppShell } from "@/components/layout/MainAppShell";
import { VATDataProvider } from "@/contexts/VATDataContext";

export default function MainLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const config = getAppConfig();
  return (
    <AuthGuard>
      <VATDataProvider>
        <MainAppShell config={config}>{children}</MainAppShell>
      </VATDataProvider>
    </AuthGuard>
  );
}
