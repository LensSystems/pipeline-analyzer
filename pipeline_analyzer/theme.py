"""Estilos compartidos del reporte HTML y del historial: tokens de color, tipografía del sistema y componentes base.

La tipografía es la del sistema (San Francisco en macOS, Segoe UI Variable en Windows 11) para que el reporte se lea como
parte del equipo de quien lo abre. El acento azul es el mismo de la ventana del asistente.
"""

TOKENS = """
:root{--bg:#f3f5f8;--card:#fff;--fg:#1b2430;--muted:#5a6475;--border:#dde2ea;--line:#c5ccd8;--ok:#177a52;--okbg:#e0f3ea;
--bad:#c3321d;--badbg:#fce9e5;--warn:#85560a;--warnbg:#fff2cf;--info:#3256d6;--infobg:#e8edfc;--code:#edf0f5;--r1:14px;--r2:10px;--r3:7px;
--display:ui-rounded,"SF Pro Rounded","Segoe UI Variable Display","Segoe UI Variable Text","Segoe UI",system-ui,sans-serif;
--font:system-ui,-apple-system,"Segoe UI Variable Text","Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
--mono:ui-monospace,SFMono-Regular,"Cascadia Mono",Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#16213e;--card:#1f2d52;--fg:#e8edf8;--muted:#a8b5d2;--border:#2f4170;--line:#4a5e94;
--ok:#6fdba7;--okbg:#1b4a46;--bad:#ff9f8f;--badbg:#5a2f45;--warn:#f2c96d;--warnbg:#4e4527;--info:#9db8ff;--infobg:#2d4580;--code:#111a33}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%;scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 var(--font);overflow-wrap:anywhere;-webkit-font-smoothing:antialiased}
a{color:var(--info)}a:focus-visible,summary:focus-visible,button:focus-visible,input:focus-visible{outline:2px solid var(--info);outline-offset:2px;border-radius:6px}
code,pre{font-family:var(--mono);font-size:13px}
h1,h2,h3{font-family:var(--display)}::selection{background:var(--infobg);color:var(--fg)}
@media (prefers-reduced-motion:reduce){html{scroll-behavior:auto}*{transition:none!important}}
"""
