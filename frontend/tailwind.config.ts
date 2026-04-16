import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        ui: {
          app: "var(--ui-surface-app)",
          surface: "var(--ui-surface-1)",
          surfaceElevated: "var(--ui-surface-2)",
          text: "var(--ui-text-primary)",
          textMuted: "var(--ui-text-muted)",
          border: "var(--ui-border)",
          accent: "var(--ui-accent)",
          accentStrong: "var(--ui-accent-strong)",
          danger: "var(--ui-danger)",
          warning: "var(--ui-warning)",
          success: "var(--ui-success)",
        },
      },
      spacing: {
        1: "var(--space-1)",
        2: "var(--space-2)",
        3: "var(--space-3)",
        4: "var(--space-4)",
        5: "var(--space-5)",
        6: "var(--space-6)",
      },
      borderRadius: {
        sm: "var(--radius-sm)",
        md: "var(--radius-md)",
        lg: "var(--radius-lg)",
      },
      boxShadow: {
        sm: "var(--shadow-sm)",
        md: "var(--shadow-md)",
      },
      transitionDuration: {
        fast: "var(--motion-fast)",
        base: "var(--motion-base)",
      },
    },
  },
  plugins: [],
};

export default config;
