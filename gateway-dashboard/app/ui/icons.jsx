"use client";

/**
 * Every icon the console uses, imported once, so a choice like "which icon
 * means Campaigns" lives in one file rather than as a scattered import in
 * whichever component happened to need it first.
 *
 * lucide-react, not hand-authored: the console needs roughly two dozen of
 * these across nav, the statusbar, and action buttons, and hand-drawing that
 * many risks inconsistent stroke-width and optical sizing -- the opposite of
 * what a redesign aimed at "polished" wants. It has zero runtime
 * dependencies of its own and is tree-shakeable, so only the icons actually
 * imported below ship.
 */

export {
  // Nav -- one per console section.
  LayoutDashboard as OverviewIcon,
  ShieldAlert as CampaignsIcon,
  ShieldCheck as PolicyIcon,
  SlidersHorizontal as AdaptiveIcon,
  Activity as EventsIcon,
  History as HistoryIcon,
  Settings as SettingsIcon,

  // Statusbar -- paired with the existing colored dots, additive rather than
  // a replacement for them.
  Database as RedisIcon,
  Radio as AgentIcon,
  Shield as PolicyCountIcon,
  AlertTriangle as EscalatedIcon,

  // Action buttons.
  Download as ExportIcon,
  RotateCcw as RevertIcon,
  Check as ApplyIcon,
  Trash2 as DeleteIcon,
  Plus as AddIcon,
  Pause as PauseIcon,
  Play as ResumeIcon,

  // Theme toggle, replacing the two hand-rolled SVGs that used to live in
  // chrome.jsx -- same concept, one fewer bespoke implementation.
  Sun as SunIcon,
  Moon as MoonIcon,

  // Shared Loading primitive.
  Loader2 as SpinnerIcon,

  // Shared EmptyState default.
  Inbox as EmptyIcon,
} from "lucide-react";
