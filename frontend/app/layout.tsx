import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Website Threat Scanner",
  description: "Review public website security, understand findings and follow practical remediation steps.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
