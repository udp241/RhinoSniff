namespace RhinoSniff.Models
{
    /// <summary>
    /// Phase 5 — actions that can be bound to a global hotkey.
    /// Wire-up in MainWindow.xaml.cs via <see cref="RhinoSniff.Classes.GlobalHotkeyManager"/>.
    /// </summary>
    public enum HotkeyAction
    {
        // PACKET CAPTURE
        ToggleCapture,
        ClearCapture,
        SwitchTrafficView,

        // ARP SPOOFING
        ToggleArp,

        // NAVIGATION
        GoToNetworkMonitor,
        GoToPacketFilters,
        GoToArp,
        GoToSettings,

        // EXPORT
        QuickExportCsv,
    }
}
