import "./globals.css";
import "leaflet/dist/leaflet.css";

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
      {/* Login and setup live outside the console shell: they have no session
          to poll with, and no navigation to offer. */}
      <body>{children}</body>
    </html>
  );
}
