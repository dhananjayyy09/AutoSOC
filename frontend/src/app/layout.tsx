import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AutoSOC Dashboard",
  description: "An Explainable Multi-Agent AI Platform for Autonomous Security Operations",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark antialiased">
      <body className="min-h-screen bg-background text-foreground font-sans">
        {children}
      </body>
    </html>
  );
}
