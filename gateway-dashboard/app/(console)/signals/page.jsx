import { redirect } from "next/navigation";

// Detector controls live with the settings that govern them. Keep the old URL
// working for bookmarked console links rather than leaving two edit surfaces.
export default function SignalsPage() {
  redirect("/settings");
}
