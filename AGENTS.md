<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

## Base44 Dev Environment

- **Stack**: TanStack Start (SSR React) + Vite 8 + Bun. Pure frontend — no external API keys or backend services required.
- **Run**: `docker compose -f docker-compose.base44.yml up -d` → dev server on port 3000.
- **Package manager**: Bun (`bun.lock`, `bunfig.toml`). Install with `bun install --frozen-lockfile`.
- **Dev command**: `bun run dev` → `vite dev` with SSR via Nitro. The `@lovable.dev/vite-tanstack-config` plugin bundles TanStack Start, React, Tailwind, tsconfig paths, and sandbox host/port detection — do NOT add these plugins manually in `vite.config.ts`.
- **Live reload**: Vite HMR is active; edits appear without restart. Call `reload_preview` only after compose/env changes.
- **`desktop/` directory**: Contains a separate Python-based desktop app (PayloadCaptureSuite) — not part of the web preview.
