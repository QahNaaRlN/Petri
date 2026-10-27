# Petri Live

Read-only Fibery custom app, deployed as an App view in `Petri Human View`:

<https://krmiftakhov.fibery.io/Petri_Human_View/43>

These are the application-owned source files. Fibery supplies the Vite/React host,
`src/main.tsx`, theme tokens, and `src/lib/fibery.ts`; those platform-owned files
are deliberately not forked here. Use Fibery's Custom Apps development workflow
to download the app's current complete source, overlay this `src/` directory,
run `pnpm install`, `pnpm exec tsc --noEmit` and `pnpm exec vite build`, then
upload through the app's short-lived development token. Keep that token outside
Git. The server build is authoritative and Fibery keeps app versions for rollback.

The app queries the five existing Human View databases as the signed-in user.
It refreshes every 30 seconds in the foreground, on window focus, and manually.
It does not mutate records, invent causal edges, or promote acceptance. A failed
refresh is visible and retains the last successful slice. `?spec=S-002` selects
a spec by its stable key; historical plan selection does not retarget facts.
The graph distinguishes recorded predecessor and causal relationships, shows
cross-spec boundary context, and warns about missing references or cycles.

GitHub event ingestion is a separate authenticated process described in
[Human View sync](../../../docs/human-view-sync.md). App source changes in GitHub
do not deploy the Fibery app automatically. Data synchronization and app code
deployment are separate operations.

Pure graph and selection checks need Node 24+ and no third-party packages:

```sh
node --experimental-strip-types integrations/fibery/live-app/tests/graph.test.ts
node --experimental-strip-types integrations/fibery/live-app/tests/selection.test.ts
```

Validation at initial deployment: TypeScript and local Vite build passed; Fibery
server build succeeded. Fifteen graph/selection tests and ten isolated Chromium
browser checks passed using baseline fixtures. Browser checks covered polling,
old plan selection, empty specs, error retention and mobile layout. They did not
authenticate to the real workspace or verify its theme sidecar. GitHub ingestion
still requires the repository's `FIBERY_API_TOKEN`; fixture checks are not proof
that the service credential has been installed or can write.
