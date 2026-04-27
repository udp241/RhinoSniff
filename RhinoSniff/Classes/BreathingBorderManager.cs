using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;

namespace RhinoSniff.Classes
{
    /// <summary>
    /// Animates the window accent border with a slow breathing pulse that
    /// matches the glow behavior in RhinoSSH (rhinossh_darkmode.c lines 537–670).
    ///
    /// Two borders pulse in sync:
    ///   1) The inner WPF Border — driven by ThemeManager.OnRendering which
    ///      calls ComputeBreathColor() every frame and stamps the result.
    ///   2) The outer DWM window border — driven by the DispatcherTimer in
    ///      this class which calls DwmSetWindowAttribute(DWMWA_BORDER_COLOR)
    ///      every 50ms (Win11+ only; silent no-op on older).
    ///
    /// Both read phase from the same wall-clock function so they stay in lockstep.
    /// Endpoints are derived from the current accent (user-selectable) so the
    /// breathe works with any color, not just RhinoSSH's cyan.
    ///
    /// Focus behavior matches RhinoSSH exactly: the foreground window pulses
    /// between dim and bright; all other registered windows hold the static
    /// dim color.
    /// </summary>
    public static class BreathingBorderManager
    {
        // === Config — matches rhinossh_darkmode.c ============================
        // GLOW_CYCLE_MS / GLOW_TICK_MS in the RhinoSSH source.
        private const int CycleMs = 1800;   // full sine period
        private const int TickMs = 50;      // DWM update tick (20fps)

        // === DWM P/Invoke ====================================================
        private const int DWMWA_BORDER_COLOR = 34;

        [DllImport("dwmapi.dll", PreserveSig = true)]
        private static extern int DwmSetWindowAttribute(
            IntPtr hwnd, int attr, ref uint pvAttribute, int cbAttribute);

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsWindow(IntPtr hwnd);

        // === Per-window state ================================================
        private sealed class Registered
        {
            public WeakReference<Window> WinRef;
            public IntPtr Hwnd;
            public uint LastDwmColor;   // last COLORREF written; skip redundant DWM calls
        }

        private static readonly List<Registered> _windows = new();
        private static readonly object _lock = new();
        private static DispatcherTimer _timer;

        // === Color endpoints (derived from current accent) ==================
        // Defaults match the teal default accent #00897B until ApplyAccent
        // notifies us with the real one.
        private static Color _accent    = Color.FromRgb(0x00, 0x89, 0x7B);
        private static Color _dim       = Color.FromRgb(0x00, 0x44, 0x3D);
        private static Color _bright    = Color.FromRgb(0x80, 0xC4, 0xBD);

        // === Win11 detection — DWMWA_BORDER_COLOR needs build 22000+ =========
        // Same gate as has_win11_dwm() in rhinossh_darkmode.c.
        private static readonly bool _isWin11 =
            Environment.OSVersion.Platform == PlatformID.Win32NT &&
            Environment.OSVersion.Version.Major >= 10 &&
            Environment.OSVersion.Version.Build >= 22000;

        // =====================================================================
        //  PUBLIC API
        // =====================================================================

        /// <summary>
        /// Recompute dim/bright endpoints from a new accent hex. Called by
        /// ThemeManager.ApplyAccent whenever the user picks a new color.
        /// Silently ignores invalid hex.
        /// </summary>
        public static void NotifyAccentChanged(string hex)
        {
            if (string.IsNullOrWhiteSpace(hex)) return;
            try
            {
                var c = (Color)ColorConverter.ConvertFromString(hex);
                if (c.A == 0) c.A = 0xFF;
                RecomputeEndpoints(c);
            }
            catch
            {
                // bad hex — leave endpoints as-is
            }
        }

        /// <summary>
        /// Add a window to the breathing set. Starts the DWM timer on first
        /// registration. Idempotent — safe to call multiple times per window.
        /// Auto-unregisters when the window closes.
        /// </summary>
        public static void Register(Window window)
        {
            if (window == null) return;

            // EnsureHandle() forces HWND creation even if Window.SourceInitialized
            // hasn't fired yet — matches rhinossh_apply_dark_titlebar()'s contract
            // of "safe to call on any top-level window".
            IntPtr hwnd;
            try { hwnd = new WindowInteropHelper(window).EnsureHandle(); }
            catch { return; }
            if (hwnd == IntPtr.Zero) return;

            lock (_lock)
            {
                // Skip if already registered (match rhinossh_register_breathing_border)
                foreach (var r in _windows)
                    if (r.Hwnd == hwnd) return;

                _windows.Add(new Registered
                {
                    WinRef = new WeakReference<Window>(window),
                    Hwnd = hwnd,
                    LastDwmColor = 0,   // force first-tick update
                });

                StartTimerIfNeeded();
            }

            // Hook Closed to deterministically unregister (prune-on-tick would
            // catch it anyway, but explicit cleanup is faster).
            window.Closed += OnWindowClosed;
        }

        /// <summary>
        /// Remove a window from the breathing set. Safe to call on unregistered
        /// windows. Timer self-terminates when the set empties.
        /// </summary>
        public static void Unregister(Window window)
        {
            if (window == null) return;
            IntPtr hwnd;
            try { hwnd = new WindowInteropHelper(window).Handle; }
            catch { return; }
            UnregisterHwnd(hwnd);
        }

        /// <summary>
        /// Called by ThemeManager.OnRendering every frame (~16ms @ 60fps) to
        /// get the current breathing color for a specific window's inner WPF
        /// Border. Mirrors glow_color_at() + focus check in rhinossh_darkmode.c.
        /// </summary>
        /// <param name="window">The window being stamped. null = force focused pulse.</param>
        public static Color ComputeBreathColor(Window window)
        {
            // Unfocused windows hold the static dim color (rhinossh line 603).
            if (window != null && !window.IsActive)
                return _dim;

            double s = SineValue01();
            return Lerp(_dim, _bright, s);
        }

        /// <summary>
        /// Convenience overload for callers that don't have a Window reference —
        /// always returns the pulsed (focused) color.
        /// </summary>
        public static Color ComputeFocusedBreathColor() => Lerp(_dim, _bright, SineValue01());

        // =====================================================================
        //  INTERNALS
        // =====================================================================

        /// <summary>
        /// Wall-clock-derived phase in [0,1], mapped through sine into [0,1].
        /// Using wall clock (not a counter) keeps the WPF per-frame stamping
        /// and the DWM 50ms tick in lockstep with zero sync effort.
        /// </summary>
        private static double SineValue01()
        {
            // Phase: fraction of the current cycle that's elapsed.
            long ms = (DateTime.UtcNow.Ticks / TimeSpan.TicksPerMillisecond) % CycleMs;
            double phase01 = (double)ms / CycleMs;     // [0,1)
            // Map to sine in [0,1] — same formula as rhinossh glow_color_at().
            return (Math.Sin(phase01 * 2.0 * Math.PI) + 1.0) * 0.5;
        }

        private static void RecomputeEndpoints(Color accent)
        {
            _accent = accent;
            // Dim = accent × 0.5 (darker half). Bright = halfway to white.
            // Wider swing than a simple shade/tint so the breathe reads visually
            // even around a 3px solid inner border.
            _dim = Color.FromArgb(0xFF,
                (byte)(accent.R * 0.5),
                (byte)(accent.G * 0.5),
                (byte)(accent.B * 0.5));
            _bright = Color.FromArgb(0xFF,
                (byte)(accent.R + (255 - accent.R) * 0.5),
                (byte)(accent.G + (255 - accent.G) * 0.5),
                (byte)(accent.B + (255 - accent.B) * 0.5));

            // Force every registered window's DWM cache to re-apply on next tick,
            // otherwise old color stays until focus changes.
            lock (_lock)
            {
                foreach (var r in _windows) r.LastDwmColor = 0;
            }
        }

        private static Color Lerp(Color a, Color b, double t)
        {
            return Color.FromArgb(
                0xFF,
                (byte)(a.R + (b.R - a.R) * t),
                (byte)(a.G + (b.G - a.G) * t),
                (byte)(a.B + (b.B - a.B) * t));
        }

        // DWM COLORREF is 0x00BBGGRR (BGR byte order, alpha ignored).
        private static uint ToColorref(Color c) =>
            (uint)(c.R | (c.G << 8) | (c.B << 16));

        private static void StartTimerIfNeeded()
        {
            if (_timer != null) return;
            _timer = new DispatcherTimer(DispatcherPriority.Render)
            {
                Interval = TimeSpan.FromMilliseconds(TickMs),
            };
            _timer.Tick += OnTimerTick;
            _timer.Start();
        }

        private static void StopTimer()
        {
            if (_timer == null) return;
            _timer.Stop();
            _timer.Tick -= OnTimerTick;
            _timer = null;
        }

        /// <summary>
        /// Mirrors glow_timer_proc() in rhinossh_darkmode.c. Walks registered
        /// windows; applies lit color to the foreground HWND, dim to all others;
        /// skips DWM call if color hasn't changed; prunes dead HWNDs; kills
        /// timer when list is empty.
        /// </summary>
        private static void OnTimerTick(object sender, EventArgs e)
        {
            // Only Win11+ has DWMWA_BORDER_COLOR. On Win10 the WPF inner border
            // still breathes (via OnRendering), just without the OS ring.
            if (!_isWin11) return;

            Color lit = Lerp(_dim, _bright, SineValue01());
            uint litRef = ToColorref(lit);
            uint dimRef = ToColorref(_dim);
            IntPtr fg = GetForegroundWindow();

            lock (_lock)
            {
                for (int i = _windows.Count - 1; i >= 0; i--)
                {
                    var r = _windows[i];
                    if (r.Hwnd == IntPtr.Zero || !IsWindow(r.Hwnd))
                    {
                        _windows.RemoveAt(i);
                        continue;
                    }

                    uint desired = (r.Hwnd == fg) ? litRef : dimRef;
                    if (desired != r.LastDwmColor)
                    {
                        DwmSetWindowAttribute(r.Hwnd, DWMWA_BORDER_COLOR, ref desired, sizeof(uint));
                        r.LastDwmColor = desired;
                    }
                }

                if (_windows.Count == 0)
                    StopTimer();
            }
        }

        private static void OnWindowClosed(object sender, EventArgs e)
        {
            if (sender is not Window w) return;
            w.Closed -= OnWindowClosed;
            try
            {
                IntPtr hwnd = new WindowInteropHelper(w).Handle;
                UnregisterHwnd(hwnd);
            }
            catch { /* nothing sane to do */ }
        }

        private static void UnregisterHwnd(IntPtr hwnd)
        {
            if (hwnd == IntPtr.Zero) return;
            lock (_lock)
            {
                for (int i = _windows.Count - 1; i >= 0; i--)
                {
                    if (_windows[i].Hwnd == hwnd)
                        _windows.RemoveAt(i);
                }
                if (_windows.Count == 0)
                    StopTimer();
            }
        }
    }
}
