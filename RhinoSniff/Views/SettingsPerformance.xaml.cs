using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using RhinoSniff.Interfaces;
using RhinoSniff.Windows;

namespace RhinoSniff.Views
{
    /// <summary>
    /// Phase 6 — Settings → Performance sub-page.
    /// Max IPs in memory + capture buffer size (KB → SharpPcap KernelBufferSize at next capture start).
    /// </summary>
    public partial class SettingsPerformance : UserControl
    {
        private readonly MainWindow _host;
        private bool _loaded;

        private const int MaxPacketsMin = 500;
        private const int MaxPacketsMax = 50000;
        private const int MaxPacketsStep = 500;

        private const int BufferMin = 64;
        private const int BufferMax = 16384;
        private const int BufferStep = 64;

        public SettingsPerformance(MainWindow host)
        {
            InitializeComponent();
            _host = host;
            LoadState();
            _loaded = true;
        }

        private void LoadState()
        {
            var mp = Clamp(Globals.Settings.MaxPacketsInMemory, MaxPacketsMin, MaxPacketsMax);
            MaxPacketsSlider.Value = mp;
            MaxPacketsField.Text = mp.ToString();

            var bf = Clamp(Globals.Settings.CaptureBufferSizeKb, BufferMin, BufferMax);
            BufferSlider.Value = bf;
            BufferField.Text = bf.ToString();
        }

        private static int Clamp(int v, int lo, int hi) => v < lo ? lo : v > hi ? hi : v;

        private async void Persist()
        {
            if (!_loaded) return;
            try { await Globals.Container.GetInstance<IServerSettings>().UpdateSettingsAsync(); }
            catch { }
        }

        // ── Max packets ──────────────────────────────────────────────────
        private void ApplyMaxPackets(int v, bool fromSlider)
        {
            v = Clamp(v, MaxPacketsMin, MaxPacketsMax);
            Globals.Settings.MaxPacketsInMemory = v;
            if (!fromSlider) MaxPacketsSlider.Value = v;
            MaxPacketsField.Text = v.ToString();
            Persist();
        }

        private void MaxPacketsSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (!_loaded) return;
            var v = (int)MaxPacketsSlider.Value;
            Globals.Settings.MaxPacketsInMemory = Clamp(v, MaxPacketsMin, MaxPacketsMax);
            MaxPacketsField.Text = Globals.Settings.MaxPacketsInMemory.ToString();
            Persist();
        }

        private void MaxPacketsField_LostFocus(object sender, RoutedEventArgs e) => CommitMaxPacketsField();
        private void MaxPacketsField_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) CommitMaxPacketsField();
        }

        private void CommitMaxPacketsField()
        {
            if (int.TryParse(MaxPacketsField.Text, out var v)) ApplyMaxPackets(v, false);
            else MaxPacketsField.Text = Globals.Settings.MaxPacketsInMemory.ToString();
        }

        private void MaxPacketsMinus_Click(object sender, RoutedEventArgs e) =>
            ApplyMaxPackets(Globals.Settings.MaxPacketsInMemory - MaxPacketsStep, false);
        private void MaxPacketsPlus_Click(object sender, RoutedEventArgs e) =>
            ApplyMaxPackets(Globals.Settings.MaxPacketsInMemory + MaxPacketsStep, false);

        // ── Buffer ───────────────────────────────────────────────────────
        private void ApplyBuffer(int v, bool fromSlider)
        {
            v = Clamp(v, BufferMin, BufferMax);
            Globals.Settings.CaptureBufferSizeKb = v;
            if (!fromSlider) BufferSlider.Value = v;
            BufferField.Text = v.ToString();
            Persist();
        }

        private void BufferSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (!_loaded) return;
            var v = (int)BufferSlider.Value;
            Globals.Settings.CaptureBufferSizeKb = Clamp(v, BufferMin, BufferMax);
            BufferField.Text = Globals.Settings.CaptureBufferSizeKb.ToString();
            Persist();
        }

        private void BufferField_LostFocus(object sender, RoutedEventArgs e) => CommitBufferField();
        private void BufferField_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) CommitBufferField();
        }

        private void CommitBufferField()
        {
            if (int.TryParse(BufferField.Text, out var v)) ApplyBuffer(v, false);
            else BufferField.Text = Globals.Settings.CaptureBufferSizeKb.ToString();
        }

        private void BufferMinus_Click(object sender, RoutedEventArgs e) =>
            ApplyBuffer(Globals.Settings.CaptureBufferSizeKb - BufferStep, false);
        private void BufferPlus_Click(object sender, RoutedEventArgs e) =>
            ApplyBuffer(Globals.Settings.CaptureBufferSizeKb + BufferStep, false);
    }
}
