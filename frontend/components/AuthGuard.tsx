"use client";

import { useEffect } from "react";
import { useRouter, usePathname } from "next/navigation";
import { useAuth } from "@/contexts/AuthContext";

const LOGIN_PATH = "/login";

export function AuthGuard({ children }: { children: React.ReactNode }) {
  const { user, initialized } = useAuth();
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    if (!initialized) return;
    if (pathname === LOGIN_PATH) return;
    if (!user) {
      router.replace(LOGIN_PATH);
    }
  }, [initialized, user, pathname, router]);

  if (pathname === LOGIN_PATH) return <>{children}</>;
  if (!initialized) return null;
  if (!user) return null;
  return <>{children}</>;
}
