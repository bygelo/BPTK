# Lane S log — x86-64 window/dialog creation to the message loop

Realize the x86-64 window/dialog-creation path so PuTTY (corpus-001) reaches its
message loop past `user32.dll!CreateDialogParamA`. Base tip `f0c2589`.

## Cycle 1 — RT_DIALOG instantiation + WM_INITDIALOG guest re-entry + x64 message pump

### What was built (all owned files)
- **`lib/rsrc.mjs` (new)** — the PE `.rsrc` resource reader and RT_DIALOG parser:
  walks the type→name→language directory tree (`findDialogResource`), decodes a
  classic `DLGTEMPLATE` and an extended `DLGTEMPLATEEX` header, the `sz_Or_Ord`
  name fields, the `DS_SETFONT` font block, and each `DLGITEMTEMPLATE` control
  (class atom → name, id, style, geometry). Read-only, bounds-checked.
- **`lib/user.mjs`** — the subsystem gains `instantiateDialog(template, dlgProc,
  initParam)` (creates the frame window + one child window per control, carries
  the guest DlgProc), `registerClassGuest` (a class whose WndProc is guest code,
  inherited by every window of the class), `getGuestWndProc`, `getDlgItem`,
  `setActiveWindow`, `setFocusWindow`, and `WM_INITDIALOG`/`WM_COMMAND`. The
  shared USER32 export table is **unchanged** (the forbidden HLE fixes its
  conformance ledger).
- **`lib/exec64.mjs`** — the x86-64 dispatch path serves the window/dialog
  surface itself, in the 64-bit ABI/struct layout:
  - `CreateDialogParam(A/W)` / `DialogBoxParam(A/W)` → parse the real RT_DIALOG
    template, instantiate real window objects, then **re-enter the guest DlgProc
    with `WM_INITDIALOG`** as real guest control flow (a return-sentinel frame,
    like the `_initterm` runner), resuming the caller with the real HWND.
  - `RegisterClass(Ex)(A/W)` and the MSG message-loop calls (`GetMessage`,
    `PeekMessage`, `TranslateMessage`, `DispatchMessage`) marshaled in the x64
    `WNDCLASS`/`MSG` layout; `DispatchMessage` re-enters the guest WndProc for a
    window that carries one. `GetMessage` on an empty queue yields a synthesized
    `WM_QUIT` — the bounded, deterministic empty input trace.
  - The scalar window/dialog exports the GUI path reaches after CreateDialog
    (`SetActiveWindow`, `CreateWindowExA`, `GetDlgItem`, `EndDialog`, …) served
    over the shared window manager.

### Frontier before → after (execution:{profile:i386_probe_v1, budget:10,000,000})
- PuTTY (001): **26318 → 30465**. Before: `import_present` at
  `user32.dll!CreateDialogParamA` (its WinMain configuration dialog). After:
  CreateDialogParamA parses the real RT_DIALOG (id 111, "About PuTTY", 4
  controls), instantiates the frame + controls, **dispatches WM_INITDIALOG into
  the guest DlgProc** (0x14000da10), returns the HWND; WinMain then runs
  `SetActiveWindow`, registers its main window class (`RegisterClassA`), creates
  the main window (`CreateWindowExA`), and stops at a genuine deeper gap:
  **`ole32.dll!CoInitialize`** — a COM export owned by the (forbidden) HLE, not
  the window/dialog surface. Named honest stop. Two runs identical.
- Corpus `bin/bptk.mjs corpus run`: 9 `entry`, 2 `loaded` — no regression.

### Did it enter the message loop / dispatch WM_INITDIALOG?
- **WM_INITDIALOG: yes** — dispatched to the real guest DlgProc as guest control
  flow (verified in PuTTY and by the synthetic-template test).
- **Message loop: reached in the unit path, not by PuTTY** — PuTTY calls
  `CoInitialize` during window setup, before its message pump, and that ole32
  import is unserved (HLE territory, forbidden to edit). The bounded x64 message
  pump (GetMessage/DispatchMessage + WndProc re-entry + WM_QUIT termination) is
  exercised by `test/exec64.test.mjs`.

### Tests (all green)
- `test/rsrc.test.mjs` (new): classic + extended template decode, the
  type→name→language walk, load-by-id.
- `test/exec64.test.mjs`: a synthetic RT_DIALOG instantiates its control and
  dispatches WM_INITDIALOG (carrying dwInitParam) to a guest DlgProc; a bounded
  message loop pumps a scripted trace, re-enters the guest WndProc once, and
  terminates on the synthesized WM_QUIT — identical across two runs.
- `test/user.test.mjs`: `instantiateDialog` / `getDlgItem` / `registerClassGuest`.

### Guarantees
`npm run gate` exits 0 (validate.py + 552 tests + check:package). `passing`
stays 0 (reaching the dialog/loop is not playable). Window/dialog creation is
REAL — the actual template is parsed, real window objects are created, the guest
DlgProc runs as guest code; nothing is faked past CreateDialog. No visible
pixels are claimed (there is no display). New file `lib/rsrc.mjs` registered in
the three gate surfaces.
