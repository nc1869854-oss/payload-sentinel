/**
 * Ownership, contact and application identity.
 *
 * Mirrors desktop/config/owner.py so the console and the desktop program never
 * disagree about who owns the suite or where to reach them.
 */

export const APP = {
  name: "Payload Capture Suite",
  short: "PCS",
  version: "2.0.0",
  edition: "Final Edition",
  tagline: "Offline network forensics and payload analysis",
  description:
    "A self-contained network forensics console: capture, payload inspection, behaviour detection, evidence handling and reporting that all run on your own machine with no API keys, accounts or telemetry.",
} as const;

export const OWNER = {
  name: "Avimanyu Singh Chauhan",
  role: "Owner and Lead Developer",
  email: "rockniraj311@gmail.com",
  handle: "@avimanyusingh53",
  location: "India",
} as const;

export type SocialLink = {
  label: string;
  url: string;
  icon:
    | "instagram"
    | "twitter"
    | "github"
    | "youtube"
    | "linkedin"
    | "facebook"
    | "send";
};

export const SOCIAL_LINKS: SocialLink[] = [
  { label: "Instagram", url: "https://instagram.com/avimanyusingh53", icon: "instagram" },
  { label: "X (Twitter)", url: "https://x.com/avimanyusingh53", icon: "twitter" },
  { label: "GitHub", url: "https://github.com/avimanyusingh53", icon: "github" },
  { label: "YouTube", url: "https://youtube.com/@avimanyusingh53", icon: "youtube" },
  { label: "LinkedIn", url: "https://linkedin.com/in/avimanyusingh53", icon: "linkedin" },
  { label: "Facebook", url: "https://facebook.com/avimanyusingh53", icon: "facebook" },
  { label: "Telegram", url: "https://t.me/avimanyusingh53", icon: "send" },
];

export const COPYRIGHT = `© 2026 ${OWNER.name}. All rights reserved.`;

export const OFFLINE_NOTICE =
  "Runs fully offline. No API keys, no accounts, no telemetry. Capture traffic only on networks you own or are authorised to monitor.";
