import type { Metadata } from "next";
import { IBM_Plex_Sans, JetBrains_Mono } from "next/font/google";
import { NuqsAdapter } from "nuqs/adapters/next/app";
import "./globals.css";
import { AuthProvider } from "@/contexts/AuthContext";
import { ThemeProvider } from "@/contexts/ThemeContext";
import { UserPreferencesProvider } from "@/contexts/UserPreferencesContext";

const ibmPlexSans = IBM_Plex_Sans({
  weight: ["400", "500", "600"],
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
      className={`${ibmPlexSans.variable} ${jetbrainsMono.variable}`}
    >
      <head>
        <link rel="icon" href="/vat-icon.svg" type="image/svg+xml" />
      </head>
      <body className={`${ibmPlexSans.className} antialiased`}>
        <NuqsAdapter>
          <AuthProvider>
            <ThemeProvider>
              <UserPreferencesProvider>{children}</UserPreferencesProvider>
            </ThemeProvider>
          </AuthProvider>
        </NuqsAdapter>
      </body>
    </html>
  );
}
