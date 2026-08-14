# Command Center Dashboard

The operations UI is a **Next.js** app in `gateway-dashboard/`. It is not a separate Express API plus React SPA.

| Piece | Location |
| --- | --- |
| UI | `app/page.js`, `app/command-center.jsx` |
| Map | `app/traffic-map.jsx` |
| Overview API | `app/api/overview/route.js` |
| Health | `app/api/health/route.js` |
| Redis client | `lib/redis.js` |

Open **http://localhost:5177** when Compose is running. The page polls Redis-backed stats and the live event stream. Use **Light theme / Dark theme** in the header. Public source IPs are plotted on the map; Docker/private traffic is shown at the gateway site and in the local overlay.
