import type { Metadata, Viewport } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "PocketSniff — Network Observability",
  description:
    "Inspect packet metadata and capture sessions with Pocket Packet Sniffer.",
  applicationName: "Pocket Packet Sniffer",
  openGraph: {
    title: "PocketSniff — Network Observability",
    description: "A privacy-first local network analysis dashboard.",
    type: "website",
  },
};

export const viewport: Viewport = {
  colorScheme: "dark",
  themeColor: "#080d15",
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
