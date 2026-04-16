import type { Metadata } from "next";
import { Manrope, JetBrains_Mono } from "next/font/google";
import { NuqsAdapter } from "nuqs/adapters/next/app";
import "./globals.css";
import { AuthProvider } from "@/contexts/AuthContext";
import { VATQueryProvider } from "@/contexts/QueryProvider";
import { ThemeProvider } from "@/contexts/ThemeContext";
import { UserPreferencesProvider } from "@/contexts/UserPreferencesContext";

const manrope = Manrope({
  weight: ["400", "500", "600", "700"],
  subsets: ["latin"],
  display: "swap",
  variable: "--font-sans",
});
const jetbrainsMono = JetBrains_Mono({
  weight: ["400", "500", "600", "700"],
  subsets: ["latin"],
  display: "swap",
  variable: "--font-mono",
});

export const metadata: Metadata = {
  title: "VAT — Vulnerability Assessment Tracker",
  description:
    "Authoritative source of record for vulnerability and security findings",
  icons: {
    icon: { url: "/vat-icon.svg", type: "image/svg+xml" },
  },
};

/** Default theme used for SSR. Must match userPreferencesStorage DEFAULTS.themeId. */
const DEFAULT_THEME = "default";

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      data-theme={DEFAULT_THEME}
      className={`${manrope.variable} ${jetbrainsMono.variable}`}
    >
      <head>
        <link rel="icon" href="/vat-icon.svg" type="image/svg+xml" />
      </head>
      <body className={`${manrope.className} antialiased`}>
        <NuqsAdapter>
          <AuthProvider>
            <VATQueryProvider>
              <ThemeProvider>
                <UserPreferencesProvider>{children}</UserPreferencesProvider>
              </ThemeProvider>
            </VATQueryProvider>
          </AuthProvider>
        </NuqsAdapter>
      </body>
    </html>
  );
}
