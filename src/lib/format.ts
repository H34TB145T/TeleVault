import type { Category } from "./types";

const categoryMap: Record<string, Exclude<Category, "All files">> = {
  jpg: "Photos", jpeg: "Photos", png: "Photos", gif: "Photos", webp: "Photos", heic: "Photos", avif: "Photos", svg: "Photos",
  mp4: "Videos", mov: "Videos", mkv: "Videos", avi: "Videos", webm: "Videos", m4v: "Videos",
  mp3: "Audio", wav: "Audio", flac: "Audio", aac: "Audio", ogg: "Audio", m4a: "Audio",
  pdf: "Documents", doc: "Documents", docx: "Documents", txt: "Documents", md: "Documents", rtf: "Documents", xls: "Documents", xlsx: "Documents", ppt: "Documents", pptx: "Documents", csv: "Documents",
  zip: "Archives", rar: "Archives", "7z": "Archives", tar: "Archives", gz: "Archives", bz2: "Archives", xz: "Archives",
  exe: "Applications", msi: "Applications", dmg: "Applications", pkg: "Applications", appimage: "Applications", deb: "Applications", rpm: "Applications", apk: "Applications"
};

export function categoryForName(name: string): Exclude<Category, "All files"> {
  const extension = name.split(".").pop()?.toLowerCase() ?? "";
  return categoryMap[extension] ?? "Other";
}

export function formatBytes(bytes: number, precision = 1): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  const power = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** power;
  return `${value.toFixed(power === 0 ? 0 : precision)} ${units[power]}`;
}

export function formatDate(iso: string): string {
  const date = new Date(iso);
  const now = new Date();
  const sameDay = date.toDateString() === now.toDateString();
  return sameDay
    ? date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    : date.toLocaleDateString([], { day: "numeric", month: "short", year: date.getFullYear() === now.getFullYear() ? undefined : "numeric" });
}

export function formatEta(seconds?: number): string {
  if (seconds === undefined || !Number.isFinite(seconds)) return "—";
  if (seconds < 60) return `${Math.ceil(seconds)} sec`;
  if (seconds < 3600) return `${Math.ceil(seconds / 60)} min`;
  return `${Math.floor(seconds / 3600)}h ${Math.ceil((seconds % 3600) / 60)}m`;
}
