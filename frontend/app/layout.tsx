import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "IDPS Platform — Intrusion Detection & Prevention System",
  description: "Advanced Network Intrusion Detection & Prevention System",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
