using System;
using System.Linq;
using System.Windows;
using MaterialDesignThemes.Wpf;

namespace RhinoSniff.Classes
{
    /// <summary>
    /// Swaps between Dark and Light resource dictionaries at runtime.
    /// Keys in Dark.xaml and Light.xaml MUST match — controls bind via
    /// {DynamicResource KeyName} and WPF re-resolves when the dictionary changes.
    ///
    /// Also swaps MaterialDesignThemes' BundledTheme so MD-styled controls
    /// (MaterialDesignFlatButton, MaterialDesignTextBox, etc.) use the matching
    /// Body/Paper/Divider brushes. Without this, MD keeps its original BaseTheme
    /// from App.xaml and bakes dark-theme white text onto our light surfaces.
    /// </summary>
    public static class ThemeManager
    {
        private const string DarkUri = "pack://application:,,,/RhinoSniff;component/Resources/Themes/Dark.xaml";
        private const string LightUri = "pack://application:,,,/RhinoSniff;component/Resources/Themes/Light.xaml";

        public static bool IsDark { get; private set; } = true;

        public static event EventHandler ThemeChanged;

        /// <summary>
        /// Applies the requested theme. No-op if already active.
        /// </summary>
        public static void ApplyTheme(bool darkMode)
        {
            try
            {
                if (Application.Current == null) return;

                var dicts = Application.Current.Resources.MergedDictionaries;
                var targetUri = new Uri(darkMode ? DarkUri : LightUri, UriKind.Absolute);
                var targetLeaf = darkMode ? "Dark.xaml" : "Light.xaml";
                var removeLeaf = darkMode ? "Light.xaml" : "Dark.xaml";

                // Remove ANY dictionary pointing at the opposite theme (relative or absolute).
                for (int i = dicts.Count - 1; i >= 0; i--)
                {
                    var s = dicts[i].Source?.OriginalString;
                    if (s != null && s.EndsWith(removeLeaf, StringComparison.OrdinalIgnoreCase))
                        dicts.RemoveAt(i);
                }

                // Ensure target dictionary is present; if none with matching leaf, add one.
                var already = dicts.Any(d =>
                    d.Source?.OriginalString != null &&
                    d.Source.OriginalString.EndsWith(targetLeaf, StringComparison.OrdinalIgnoreCase));
                if (!already)
                {
                    dicts.Add(new ResourceDictionary { Source = targetUri });
                }

                // Swap MaterialDesign base theme so MD's own brushes (MaterialDesignBody,
                // MaterialDesignPaper, MaterialDesignDivider, etc.) track our theme.
                // Without this, MD-styled buttons keep dark-theme white text in Light mode.
                try
                {
                    var paletteHelper = new PaletteHelper();
                    var theme = paletteHelper.GetTheme();
                    theme.SetBaseTheme(darkMode ? Theme.Dark : Theme.Light);
                    paletteHelper.SetTheme(theme);
                }
                catch
                {
                    // MD theme swap is best-effort — our own dictionaries still work.
                }

                IsDark = darkMode;
                ThemeChanged?.Invoke(null, EventArgs.Empty);
            }
            catch
            {
                // Theme swap failure should never crash the app — fall back silently.
            }
        }

        /// <summary>
        /// Toggles between Dark and Light.
        /// </summary>
        public static void Toggle() => ApplyTheme(!IsDark);

        /// <summary>
        /// Patches the live AccentTeal* token brushes in App resources so all
        /// `{DynamicResource AccentTeal}` / `AccentTealDark` / `AccentBlue` bindings
        /// across the UI re-resolve to the user's chosen accent.
        ///
        /// Tokens patched:
        ///   AccentTealDark         — primary accent (active fills, key buttons)
        ///   AccentTeal             — bright variant (hover, icons)
        ///   AccentBlue / Hover     — legacy refs / Settings preview
        ///   SidebarItemActive      — active sidebar row accent + v2 badge + adapter dot
        ///   InputBorderFocus       — input focus border
        ///   ProtoBothText          — "BOTH" protocol pill text
        ///   LabelText              — label column text (alpha 0xCC preserved)
        ///   MaterialDesign palette — PrimaryColor for ALL MD-styled controls (buttons,
        ///                            icons, combo carets, progress bars, etc.)
        ///
        /// Hex must be parseable by ColorConverter (e.g. "#FFC0CB" or "#FFFFC0CB").
        /// Silently no-ops on invalid hex.
        /// </summary>
        public static void ApplyAccent(string hex)
        {
            try
            {
                // DIAG: log every ApplyAccent call so we can trace the startup flow
                try
                {
                    var logDir = System.IO.Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RhinoSniff");
                    System.IO.Directory.CreateDirectory(logDir);
                    var logPath = System.IO.Path.Combine(logDir, "accent-debug.log");
                    System.IO.File.AppendAllText(logPath,
                        $"{DateTime.Now:HH:mm:ss.fff} ApplyAccent(hex={hex ?? "null"}) settings.AccentColorHex={Globals.Settings?.AccentColorHex ?? "null"}\r\n");
                }
                catch { }

                if (Application.Current == null || string.IsNullOrWhiteSpace(hex)) return;

                var color = (System.Windows.Media.Color)
                    System.Windows.Media.ColorConverter.ConvertFromString(hex);

                // Force opaque alpha so accent tokens don't go transparent if user pasted #RGB
                if (color.A == 0) color.A = 0xFF;

                // Remember this as the last successfully applied accent so StampWindowBorder
                // can use it even if something resets Globals.Settings mid-session.
                _lastAccentHex = hex;

                // Tell the breathing-glow animator to rebuild dim/bright endpoints
                // from the new accent color. Per-frame stamping in OnRendering reads
                // these to produce the pulsed color.
                BreathingBorderManager.NotifyAccentChanged(hex);

                var accent = new System.Windows.Media.SolidColorBrush(color);
                accent.Freeze();

                // Brighter shade for hover (clamp +24 on RGB)
                var hoverColor = System.Windows.Media.Color.FromArgb(
                    0xFF,
                    (byte)Math.Min(255, color.R + 24),
                    (byte)Math.Min(255, color.G + 24),
                    (byte)Math.Min(255, color.B + 24));
                var accentBright = new System.Windows.Media.SolidColorBrush(hoverColor);
                accentBright.Freeze();

                // Semi-transparent variant for LabelText (original alpha was 0xCC)
                var labelColor = System.Windows.Media.Color.FromArgb(0xCC, color.R, color.G, color.B);
                var labelBrush = new System.Windows.Media.SolidColorBrush(labelColor);
                labelBrush.Freeze();

                var res = Application.Current.Resources;

                // Semi-transparent variants used by "soft" pills (10% alpha)
                var softColor = System.Windows.Media.Color.FromArgb(0x1A, color.R, color.G, color.B);
                var softBrush = new System.Windows.Media.SolidColorBrush(softColor);
                softBrush.Freeze();

                // Build a fresh accent overlay dictionary with EVERY accent-related brush key.
                // Putting this dict at the END of MergedDictionaries makes it the last-merged
                // entry, so its values win DynamicResource lookups over Tokens.xaml / Dark.xaml /
                // Light.xaml. Mutating MergedDictionaries also fires WPF change notifications, so
                // all live DynamicResource subscribers in all windows (current AND future) update.
                var overlay = new System.Windows.ResourceDictionary();
                overlay["AccentTealDark"]         = accent;
                overlay["AccentTeal"]             = accentBright;
                overlay["AccentBlue"]             = accent;
                overlay["AccentBlueHover"]        = accentBright;
                overlay["SidebarItemActive"]      = accentBright;
                overlay["SidebarItemSelectedBg"]  = softBrush;
                overlay["InputBorderFocus"]       = accentBright;
                overlay["ProtoBothText"]          = accentBright;
                overlay["ProtoBothBg"]            = softBrush;
                overlay["LabelText"]              = labelBrush;
                // Tag so we can find/remove this overlay on next accent change (any non-null
                // Source would force WPF to try loading a URI; use Source=null and rely on Tag).
                // Since ResourceDictionary has no Tag, we mark via a sentinel key.
                overlay["__RhinoSniffAccentOverlay"] = true;

                // Remove any previous accent overlay (identified by the sentinel key).
                for (int i = res.MergedDictionaries.Count - 1; i >= 0; i--)
                {
                    var md = res.MergedDictionaries[i];
                    if (md != null && md.Contains("__RhinoSniffAccentOverlay"))
                        res.MergedDictionaries.RemoveAt(i);
                }
                // Add fresh overlay at the end (highest priority).
                res.MergedDictionaries.Add(overlay);

                // Also patch MaterialDesign's primary palette so every MD-styled button,
                // icon, combo caret, progress bar etc. re-colors to the accent.
                try
                {
                    var paletteHelper = new PaletteHelper();
                    var theme = paletteHelper.GetTheme();
                    theme.SetPrimaryColor(color);
                    theme.SetSecondaryColor(color);
                    paletteHelper.SetTheme(theme);
                }
                catch { /* MD palette swap failure shouldn't abort the accent update */ }

                // Belt-and-suspenders: stamp BorderBrush directly on any currently-open
                // window's outer Border. Covers edge cases where a Style's setter has already
                // resolved to a cached brush that isn't re-evaluating on the overlay add.
                try
                {
                    foreach (System.Windows.Window win in Application.Current.Windows)
                    {
                        if (win == null) continue;
                        StampWindowBorder(win);
                    }
                }
                catch { /* visual-tree walk shouldn't ever crash app */ }
            }
            catch
            {
                // Bad hex / parse failure — leave accents as-is.
            }
        }

        /// <summary>
        /// Directly stamps the saved accent brush onto a window's outer Border (named "Border"
        /// in the XAML). Used from window constructors so windows opened AFTER app startup still
        /// pick up the user's accent — the resource-dict patches alone don't survive DynamicResource
        /// cache quirks across new-window loads, so we belt-and-suspenders it here.
        /// Safe to call before the window has fully initialized — it just no-ops if the Border
        /// isn't reachable yet, and callers should also invoke from their Loaded handler.
        /// </summary>
        /// <summary>
        /// Last accent hex successfully applied by ApplyAccent. StampWindowBorder prefers this over
        /// Globals.Settings.AccentColorHex when available, so the border can't regress to the default
        /// if something resets the settings object mid-session.
        /// </summary>
        private static string _lastAccentHex = null;

        public static void StampWindowBorder(System.Windows.Window window)
        {
            if (window == null || Application.Current == null) return;
            try
            {
                // Prefer the in-memory last-applied accent; fall back to persisted settings;
                // final fallback to the default teal.
                var hex = _lastAccentHex;
                var src = "lastAccent";
                if (string.IsNullOrWhiteSpace(hex)) { hex = Globals.Settings?.AccentColorHex; src = "settings"; }
                if (string.IsNullOrWhiteSpace(hex)) { hex = "#00897B"; src = "default"; }

                // DIAG: log every stamp attempt to disk so the user can share what's really happening
                try
                {
                    var logDir = System.IO.Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RhinoSniff");
                    System.IO.Directory.CreateDirectory(logDir);
                    var logPath = System.IO.Path.Combine(logDir, "accent-debug.log");
                    var line = $"{DateTime.Now:HH:mm:ss.fff} [{window.GetType().Name}] stamp hex={hex} src={src} lastAccent={_lastAccentHex ?? "null"} settings={Globals.Settings?.AccentColorHex ?? "null"}\r\n";
                    System.IO.File.AppendAllText(logPath, line);
                }
                catch { }

                var color = (System.Windows.Media.Color)
                    System.Windows.Media.ColorConverter.ConvertFromString(hex);
                if (color.A == 0) color.A = 0xFF;

                // Use the breathing color (current phase) for the initial stamp so
                // the first frame is already in-phase with OnRendering's per-frame
                // re-stamp. Uses static dim when the window is unfocused.
                var breathingColor = BreathingBorderManager.ComputeBreathColor(window);
                var brush = new System.Windows.Media.SolidColorBrush(breathingColor);
                brush.Freeze();

                var border = window.FindName("Border") as System.Windows.Controls.Border;
                if (border != null)
                {
                    border.BorderBrush = brush;
                    border.BorderThickness = new System.Windows.Thickness(3);
                }
                else
                {
                    try
                    {
                        var logDir = System.IO.Path.Combine(
                            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RhinoSniff");
                        var logPath = System.IO.Path.Combine(logDir, "accent-debug.log");
                        System.IO.File.AppendAllText(logPath,
                            $"{DateTime.Now:HH:mm:ss.fff} [{window.GetType().Name}] !! FindName('Border') returned null\r\n");
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                try
                {
                    var logDir = System.IO.Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RhinoSniff");
                    var logPath = System.IO.Path.Combine(logDir, "accent-debug.log");
                    System.IO.File.AppendAllText(logPath,
                        $"{DateTime.Now:HH:mm:ss.fff} [{window.GetType().Name}] !! EXCEPTION {ex.GetType().Name}: {ex.Message}\r\n");
                }
                catch { }
            }
        }

        // Tracks windows that have already had auto-heal events wired up so we only subscribe once.
        private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<
            System.Windows.Window, object> _hookedWindows = new();

        // Windows enrolled in per-frame border enforcement. Weak refs so GC drops closed windows
        // out of the list automatically.
        private static readonly System.Collections.Generic.List<System.WeakReference<System.Windows.Window>>
            _enforcedWindows = new();
        private static bool _renderingHooked;
        private static System.Windows.Media.Color? _expectedBorderColor;

        /// <summary>
        /// Subscribes a window to every event that can cause the accent border to revert to the
        /// Style's DynamicResource default, re-stamping on each. Covers: app boot, minimize, restore,
        /// maximize, fullscreen transitions, focus changes (alt-tab / multi-window switches), DPI
        /// changes (multi-monitor), visibility toggles, and size changes. Idempotent — safe to call
        /// multiple times per window.
        /// </summary>
        public static void HookBorderAutoHeal(System.Windows.Window window)
        {
            if (window == null) return;
            // Already hooked? Nothing to do.
            if (_hookedWindows.TryGetValue(window, out _)) return;
            _hookedWindows.Add(window, new object());

            void Restamp(object s, object e) { try { StampWindowBorder(window); } catch { } }

            // Enroll this window in per-frame enforcement. Hook CompositionTarget.Rendering
            // once globally — it fires every frame (~16ms) and re-stamps any enrolled window
            // whose border brush drifted from the expected accent color.
            _enforcedWindows.Add(new System.WeakReference<System.Windows.Window>(window));
            if (!_renderingHooked)
            {
                _renderingHooked = true;
                System.Windows.Media.CompositionTarget.Rendering += OnRendering;
            }

            // Fires once after visual tree is fully realized — covers first paint after constructor.
            window.Loaded += (s, e) => Restamp(s, e);
            // Minimize / restore / maximize / fullscreen transitions.
            window.StateChanged += (s, e) => Restamp(s, e);
            // Window gaining focus (alt-tab back, switching between app windows).
            window.Activated += (s, e) => Restamp(s, e);
            // Window losing focus — also re-stamp so it's ready when user comes back.
            window.Deactivated += (s, e) => Restamp(s, e);
            // Show/hide cycles (dialog closed, window un-collapsed, etc.)
            window.IsVisibleChanged += (s, e) => Restamp(s, e);
            // Any size change including fullscreen/maximize re-layouts.
            window.SizeChanged += (s, e) => Restamp(s, e);
            // Location changes (moved to another monitor — can trigger DPI/resource reeval).
            window.LocationChanged += (s, e) => Restamp(s, e);
            // Explicit DPI change (multi-monitor hand-off where scale differs).
            window.DpiChanged += (s, e) => Restamp(s, e);
            // Rendering started — one last safety net after full composition.
            window.ContentRendered += (s, e) => Restamp(s, e);
        }

        /// <summary>
        /// Fires every rendered frame (~16ms). Walks enrolled windows and re-stamps any whose
        /// outer Border's BorderBrush drifted from the expected accent color. This is the
        /// belt-for-the-belt-and-suspenders — catches reverts caused by anything WPF might do
        /// that our event hooks don't cover (property-system re-evaluations, template reapply,
        /// binding refresh, render-thread races, etc.).
        /// </summary>
        private static void OnRendering(object sender, EventArgs e)
        {
            try
            {
                // Walk enrolled windows; drop dead weak-refs as we go.
                for (int i = _enforcedWindows.Count - 1; i >= 0; i--)
                {
                    if (!_enforcedWindows[i].TryGetTarget(out var win) || win == null)
                    {
                        _enforcedWindows.RemoveAt(i);
                        continue;
                    }
                    var border = win.FindName("Border") as System.Windows.Controls.Border;
                    if (border == null) continue;

                    // Time-varying breathing color (unfocused windows hold dim).
                    // Endpoints come from BreathingBorderManager which rebuilds them
                    // whenever ApplyAccent fires, so this always reflects the current
                    // user-selected accent. The equality short-circuit below is kept:
                    // at the sine peaks/troughs two consecutive frames can produce the
                    // same rounded RGB bytes, and for unfocused windows the color is
                    // statically dim — both cases skip the brush allocation.
                    var expected = BreathingBorderManager.ComputeBreathColor(win);

                    var current = border.BorderBrush as System.Windows.Media.SolidColorBrush;
                    if (current != null && current.Color == expected &&
                        border.BorderThickness.Top == 3)
                        continue;

                    var brush = new System.Windows.Media.SolidColorBrush(expected);
                    brush.Freeze();
                    border.BorderBrush = brush;
                    border.BorderThickness = new System.Windows.Thickness(3);
                }
            }
            catch { /* never let a per-frame handler crash the app */ }
        }

        /// <summary>
        /// Patches the live FontFamily resource so all `{DynamicResource AppFontFamily}`
        /// bindings re-resolve. Controls that use `FontFamily="..."` literals will NOT
        /// update — Phase 7.1 leaves font literals in XAML; this hook is for future use.
        /// </summary>
        public static void ApplyFont(string fontFamily)
        {
            try
            {
                if (Application.Current == null || string.IsNullOrWhiteSpace(fontFamily)) return;

                // Bundled fonts ship inside the assembly under Resources/Fonts and need
                // the pack:// URI to resolve. System fonts can be referenced by name alone.
                System.Windows.Media.FontFamily ff;
                if (string.Equals(fontFamily, "Gotham", System.StringComparison.OrdinalIgnoreCase))
                {
                    ff = new System.Windows.Media.FontFamily(
                        new Uri("pack://application:,,,/RhinoSniff;Component/Resources/Fonts/", UriKind.Absolute),
                        "./#Gotham");
                }
                else
                {
                    ff = new System.Windows.Media.FontFamily(fontFamily);
                }

                Application.Current.Resources["AppFontFamily"] = ff;
            }
            catch { }
        }
    }
}
