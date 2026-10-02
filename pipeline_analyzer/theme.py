"""Estilos compartidos del reporte HTML y del historial: tokens de color, tipografía del sistema y componentes base.

La tipografía es la del sistema (San Francisco en macOS, Segoe UI Variable en Windows 11) para que el reporte se lea como
parte del equipo de quien lo abre. El acento azul es el mismo de la ventana del asistente.
"""

TOKENS = """
:root{--bg:#f5f6f8;--card:#fff;--fg:#1c1f26;--muted:#5b6372;--border:#dfe3ea;--ok:#1a7f55;--okbg:#e2f4ec;
--bad:#c8341f;--badbg:#fdeae6;--warn:#8a5a00;--warnbg:#fff3d1;--info:#0a67d8;--infobg:#e6f0fd;--code:#eef0f4;
--font:system-ui,-apple-system,"Segoe UI Variable Text","Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
--mono:ui-monospace,SFMono-Regular,"Cascadia Mono",Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#13151a;--card:#1b1e25;--fg:#e8eaee;--muted:#9aa2b1;--border:#2b303b;
--ok:#4cc38a;--okbg:#143023;--bad:#ff8a77;--badbg:#3a1b17;--warn:#f0bf4c;--warnbg:#35290d;--info:#6ea8fe;--infobg:#14243d;--code:#242832}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%;scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 var(--font);overflow-wrap:anywhere;-webkit-font-smoothing:antialiased}
a{color:var(--info)}a:focus-visible,summary:focus-visible,button:focus-visible,input:focus-visible{outline:2px solid var(--info);outline-offset:2px;border-radius:6px}
code,pre{font-family:var(--mono);font-size:13px}
@media (prefers-reduced-motion:reduce){html{scroll-behavior:auto}*{transition:none!important}}
"""
