import "./globals.css";
import "leaflet/dist/leaflet.css";
import { Shell } from "./ui/chrome";
import { LiveProvider } from "./ui/store";

export const metadata = {
  title: "IASG · Operations",
  description: "Security operations console for the Intelligent API Security Gateway",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" data-theme="dark" suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `try{var t=localStorage.getItem('iasg-theme');if(t==='light'||t==='dark')document.documentElement.setAttribute('data-theme',t)}catch(e){}`,
          }}
        />
      </head>
      <body>
        {/* Polling lives above the router, so moving between pages neither
            restarts the clock nor blanks the screen. */}
        <LiveProvider>
          <Shell>{children}</Shell>
        </LiveProvider>
      </body>
    </html>
  );
}
