using System;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using RhinoSniff.Classes;
using RhinoSniff.Interfaces;
using RhinoSniff.Models;
using RhinoSniff.Windows;

namespace RhinoSniff.Views
{
    /// <summary>
    /// Phase 6 — Settings → Appearance sub-page.
    /// Dark/Light theme, accent color, background image (with BUG #1 GUID-copy fix).
    /// </summary>
    public partial class SettingsAppearance : UserControl
    {
        private readonly MainWindow _host;
        private bool _loaded;

        /// <summary>v2.9.3 — default accent hex. Teal, matches the "Teal" swatch.</summary>
        private const string DefaultAccentHex = "#00897B";

        /// <summary>Cache of swatch buttons so we can toggle selection state cheaply.</summary>
        private System.Collections.Generic.List<System.Windows.Controls.Button> _swatchButtons;

        private static readonly string[] AllowedExt =
            { ".jpg", ".jpeg", ".png", ".bmp", ".jfif", ".gif" };

        public SettingsAppearance(MainWindow host)
        {
            InitializeComponent();
            _host = host;
            LoadState();
            _loaded = true;
        }

        private void LoadState()
        {
            UpdateThemeButtons(Globals.Settings.DarkMode);

            // Cache swatches once. They all share AccentSwatchStyle and store hex in Tag.
            _swatchButtons = new System.Collections.Generic.List<System.Windows.Controls.Button>
            {
                SwatchCyan, SwatchBlue, SwatchPurple, SwatchPink, SwatchRed,
                SwatchOrange, SwatchYellow, SwatchGreen, SwatchTeal
            };

            // Reflect saved accent: if it matches a preset, highlight it; otherwise fall back to Teal.
            var saved = Globals.Settings.AccentColorHex ?? DefaultAccentHex;
            UpdateSelectedSwatch(saved);
            UpdateBackgroundLabel();

            // Font dropdown: pick the matching ComboBoxItem by Content text. If the user's
            // saved font isn't in our preset list, we just leave nothing selected (still works).
            try
            {
                var savedFont = Globals.Settings.FontFamily ?? "Gotham";
                foreach (var item in FontFamilyCombo.Items)
                {
                    if (item is System.Windows.Controls.ComboBoxItem cbi &&
                        string.Equals(cbi.Content?.ToString(), savedFont, System.StringComparison.OrdinalIgnoreCase))
                    {
                        FontFamilyCombo.SelectedItem = cbi;
                        break;
                    }
                }
            }
            catch { }
        }

        private void FontFamilyCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (!_loaded) return;
            if (FontFamilyCombo.SelectedItem is not System.Windows.Controls.ComboBoxItem cbi) return;
            var name = cbi.Content?.ToString();
            if (string.IsNullOrWhiteSpace(name)) return;
            Globals.Settings.FontFamily = name;
            ThemeManager.ApplyFont(name);
            _ = Persist();
        }

        private void UpdateBackgroundLabel()
        {
            var bg = Globals.Settings.Background;
            BackgroundLabel.Text = string.IsNullOrWhiteSpace(bg) || bg == "None"
                ? "Selected: None"
                : "Selected: " + Path.GetFileName(bg);
        }

        private void UpdateThemeButtons(bool dark)
        {
            try
            {
                var raised = (Style)Application.Current.FindResource("MaterialDesignRaisedButton");
                var outlined = (Style)Application.Current.FindResource("MaterialDesignOutlinedButton");
                ThemeDarkButton.Style  = dark ? raised : outlined;
                ThemeLightButton.Style = dark ? outlined : raised;
            }
            catch { }
        }

        private async System.Threading.Tasks.Task Persist()
        {
            if (!_loaded) return;
            try { await Globals.Container.GetInstance<IServerSettings>().UpdateSettingsAsync(); }
            catch { }
        }

        // ── Theme ────────────────────────────────────────────────────────
        private void ThemeDarkButton_Click(object sender, RoutedEventArgs e)
        {
            Globals.Settings.DarkMode = true;
            ThemeManager.ApplyTheme(true);
            UpdateThemeButtons(true);
            _ = Persist();
        }

        private void ThemeLightButton_Click(object sender, RoutedEventArgs e)
        {
            Globals.Settings.DarkMode = false;
            ThemeManager.ApplyTheme(false);
            UpdateThemeButtons(false);
            _ = Persist();
        }

        // ── Accent color (v2.9.3 — preset swatches) ─────────────────────────

        /// <summary>
        /// Highlights the swatch whose Tag matches <paramref name="hex"/> (case-insensitive).
        /// Also toggles the inner check-mark PackIcon on the matching swatch. If no swatch
        /// matches, all are left unselected — this happens only if a user previously set
        /// a custom hex via an older build; hitting any swatch resolves it.
        /// </summary>
        private void UpdateSelectedSwatch(string hex)
        {
            if (_swatchButtons == null) return;
            try
            {
                foreach (var btn in _swatchButtons)
                {
                    var tagHex = btn.Tag as string ?? "";
                    var isSel = string.Equals(tagHex.TrimStart('#'), (hex ?? "").TrimStart('#'),
                                              System.StringComparison.OrdinalIgnoreCase);

                    // Border highlight: accent color when selected, card border otherwise.
                    btn.BorderBrush = isSel
                        ? (System.Windows.Media.Brush)Application.Current.Resources["AccentTealDark"]
                        : (System.Windows.Media.Brush)Application.Current.Resources["CardBorder"];
                    btn.BorderThickness = new Thickness(isSel ? 2 : 1);

                    // Find the check PackIcon inside the button content and toggle visibility.
                    var checkIcon = FindSwatchCheck(btn);
                    if (checkIcon != null)
                        checkIcon.Visibility = isSel ? Visibility.Visible : Visibility.Collapsed;
                }
            }
            catch { /* non-fatal — visual-only */ }
        }

        /// <summary>Walks the button's StackPanel to find the Check PackIcon overlay.</summary>
        private static MaterialDesignThemes.Wpf.PackIcon FindSwatchCheck(System.Windows.Controls.Button btn)
        {
            if (btn.Content is not System.Windows.Controls.StackPanel sp) return null;
            foreach (var child in sp.Children)
            {
                if (child is System.Windows.Controls.Grid g)
                    foreach (var inner in g.Children)
                        if (inner is MaterialDesignThemes.Wpf.PackIcon icon)
                            return icon;
            }
            return null;
        }

        private void AccentSwatch_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not System.Windows.Controls.Button btn) return;
            var hex = btn.Tag as string;
            if (string.IsNullOrWhiteSpace(hex)) return;
            _ = ApplyAccentHexAsync(hex);
        }

        /// <summary>Applies + persists the given accent hex. Called by swatch click and Reset.</summary>
        private async System.Threading.Tasks.Task ApplyAccentHexAsync(string hex)
        {
            if (string.IsNullOrWhiteSpace(hex)) return;
            if (!hex.StartsWith("#")) hex = "#" + hex;
            try
            {
                // Validate — ColorConverter throws on malformed input.
                _ = (Color)ColorConverter.ConvertFromString(hex);
                Globals.Settings.AccentColorHex = hex;
                // Keep legacy HexColor in sync too so older code paths / file reads that still
                // look at HexColor see the same value. Belt-and-suspenders against startup revert.
                Globals.Settings.HexColor = hex;
                ThemeManager.ApplyAccent(hex);
                UpdateSelectedSwatch(hex);
                // AWAIT the save so the swatch click is guaranteed to hit disk before the handler
                // returns. Previously this was fire-and-forget which could lose the write if the
                // user closed the app within ~50ms of clicking a swatch.
                await Persist();
            }
            catch { /* bad hex in a preset would be a dev bug — ignore silently */ }
        }

        private void AccentResetButton_Click(object sender, RoutedEventArgs e)
        {
            _ = ApplyAccentHexAsync(DefaultAccentHex);
        }

        // ── Background (BUG #1 fix: copy picked file into %APPDATA%\RhinoSniff\Backgrounds\{guid}{ext}) ─
        private async void PickImageButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var ofd = new OpenFileDialog
                {
                    Filter = "Supported image files (*.jpg, *.jpeg, *.png, *.bmp, *.jfif, *.gif) | *.jpg; *.jpeg; *.png; *.bmp; *.jfif; *.gif",
                    Title = "Select background image...",
                    CheckFileExists = true,
                    CheckPathExists = true,
                    ValidateNames = true,
                    InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    Multiselect = false
                };
                if (ofd.ShowDialog() != true) return;

                var ext = Path.GetExtension(ofd.FileName) ?? "";
                if (!System.Array.Exists(AllowedExt, x =>
                        string.Equals(x, ext, StringComparison.OrdinalIgnoreCase)))
                {
                    try { _host?.NotifyPublic(NotificationType.Alert, "Unsupported image format."); } catch { }
                    return;
                }
                try
                {
                    if (!Globals.Container.GetInstance<IThemeUtils>().IsImage(ofd.FileName))
                    {
                        try { _host?.NotifyPublic(NotificationType.Alert, "Selected file is not a valid image."); } catch { }
                        return;
                    }
                }
                catch { /* IThemeUtils missing — fall through, extension check already gate-kept */ }

                // BUG #1: copy into %APPDATA%\RhinoSniff\Backgrounds\{guid}{ext} so we don't lose
                // the wallpaper if the user moves/deletes the source file from Downloads.
                var dir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "RhinoSniff", "Backgrounds");
                Directory.CreateDirectory(dir);

                // Best-effort: delete any previously-copied background to keep the folder tidy.
                TryDeleteManagedBackground(Globals.Settings.Background);

                var dest = Path.Combine(dir, Guid.NewGuid().ToString("N") + ext);
                File.Copy(ofd.FileName, dest, overwrite: false);

                Globals.Settings.Background = dest.Replace('\\', '/');
                _host?.PublicLoadBackground(Globals.Settings.Background);
                UpdateBackgroundLabel();
                _ = Persist();
            }
            catch (Exception ex)
            {
                try { _host?.NotifyPublic(NotificationType.Error, "Failed to apply background image."); } catch { }
                await ex.AutoDumpExceptionAsync();
            }
        }

        private void ClearBackgroundButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                TryDeleteManagedBackground(Globals.Settings.Background);
                Globals.Settings.Background = "None";
                _host?.PublicClearBackground();
                UpdateBackgroundLabel();
                _ = Persist();
            }
            catch (Exception ex) { _ = ex.AutoDumpExceptionAsync(); }
        }

        /// <summary>
        /// If <paramref name="path"/> points into our managed Backgrounds folder,
        /// delete it. Never deletes files outside that folder (legacy paths from
        /// pre-Phase 6 installs that still point at wherever the user picked).
        /// </summary>
        private static void TryDeleteManagedBackground(string path)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path) || path == "None") return;
                var full = Path.GetFullPath(path.Replace('/', Path.DirectorySeparatorChar));
                var managedDir = Path.GetFullPath(Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "RhinoSniff", "Backgrounds"));
                if (!full.StartsWith(managedDir, StringComparison.OrdinalIgnoreCase)) return;
                if (File.Exists(full)) File.Delete(full);
            }
            catch { /* non-fatal */ }
        }

        private void ResetAppearanceButton_Click(object sender, RoutedEventArgs e)
        {
            // Theme → Dark, accent → default (Teal), font → default, background → None.
            Globals.Settings.DarkMode = true;
            ThemeManager.ApplyTheme(true);
            UpdateThemeButtons(true);

            Globals.Settings.AccentColorHex = DefaultAccentHex;
            ThemeManager.ApplyAccent(DefaultAccentHex);
            UpdateSelectedSwatch(DefaultAccentHex);

            const string defFont = "Gotham";
            Globals.Settings.FontFamily = defFont;
            ThemeManager.ApplyFont(defFont);
            try { if (FontFamilyCombo != null) FontFamilyCombo.SelectedItem = defFont; } catch { }

            TryDeleteManagedBackground(Globals.Settings.Background);
            Globals.Settings.Background = "None";
            _host?.PublicClearBackground();
            UpdateBackgroundLabel();

            _ = Persist();
        }
    }
}
