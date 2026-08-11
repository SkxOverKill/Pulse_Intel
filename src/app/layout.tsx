import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Pulse Intelligence",
  description: "Threat intelligence platform — actors, campaigns, IOCs, ATT&CK.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      {/* suppressHydrationWarning: browser extensions (Grammarly, password
          managers, etc.) inject data-* attributes onto <body> before React
          hydrates. That's an extension modifying the DOM, not an app bug —
          without this, React logs a hydration-mismatch warning for every
          visitor who has one of those extensions installed. */}
      <body className="min-h-full bg-base font-sans text-ink" suppressHydrationWarning>
        {children}
      </body>
    </html>
  );
}
