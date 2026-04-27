using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Media;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using RhinoSniff.Classes;
using RhinoSniff.Interfaces;
using RhinoSniff.Models;
using RhinoSniff.Views;
using MaterialDesignThemes.Wpf;
using Microsoft.Win32;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using SharpPcap.Npcap;
using WpfAnimatedGif;
using static RhinoSniff.Extensions;
using Label = RhinoSniff.Models.Label;
using Theme = RhinoSniff.Models.Theme;

namespace RhinoSniff.Windows;

[Obfuscation(Feature = "apply to member * when constructor: virtualization", Exclude = false)]
public partial class MainWindow : Window
{
    public static readonly RoutedUICommand AnalyseCommand =
        new("Analyse", "AnalyseCommand", typeof(MainWindow));

    public static readonly RoutedUICommand ClearAllCommand =
        new("Clear", "ClearAllCommand", typeof(MainWindow));

    public static readonly RoutedUICommand MoveToGamesCommand =
        new("Move to Games", "MoveToGamesCommand", typeof(MainWindow));

    public static readonly RoutedUICommand CopyCommand =
        new("Copy", "CopyCommand", typeof(MainWindow));

    public static readonly RoutedUICommand ExportCommand =
        new("Export", "ExportCommand", typeof(MainWindow));

    public static readonly RoutedUICommand ExportPcapCommand =
        new("Export PCAP", "ExportPcapCommand", typeof(MainWindow));

    public static readonly RoutedUICommand ExportTheme =
        new("Export", "ExportTheme", typeof(MainWindow));

    public static readonly RoutedUICommand WhoisAllCommand =
        new("WHOIS All", "WhoisAllCommand", typeof(MainWindow));

    public static readonly RoutedUICommand HandleCaptions =
        new("Handle captions", "HandleCaptions", typeof(MainWindow));

    public static readonly RoutedUICommand HideSideView =
        new("Hide side view", "HideSideView", typeof(MainWindow));

    public static readonly RoutedUICommand HideNotification =
        new("Hide notification", "HideNotification", typeof(MainWindow));

    public static readonly RoutedUICommand ImportTheme =
        new("Import", "ImportTheme", typeof(MainWindow));

    public static readonly DependencyProperty IsDialogOpenProperty =
        DependencyProperty.Register("IsDialogOpen", typeof(bool),
            typeof(Window), new UIPropertyMetadata(false));

    public static readonly DependencyProperty IsSniffingProperty =
        DependencyProperty.Register("IsSniffing", typeof(bool),
            typeof(Window), new UIPropertyMetadata(false));

    public static readonly RoutedUICommand LabelCommand =
        new("Add to labels", "LabelCommand", typeof(MainWindow));

    public static readonly RoutedUICommand LocateCommand =
        new("Locate", "LocateCommand", typeof(MainWindow));

    public static readonly RoutedUICommand OpenAdapter =
        new("Open adapter", "OpenAdapter", typeof(MainWindow));

    public static readonly RoutedUICommand OpenArp =
        new("Open Arp", "OpenArp", typeof(MainWindow));

    public static readonly RoutedUICommand OpenFilters =
        new("Open filters", "OpenFilters", typeof(MainWindow));

    public static readonly RoutedUICommand OpenLog =
        new("Open log", "OpenLog", typeof(MainWindow));

    public static readonly RoutedUICommand OpenSettings =
        new("Open settings", "OpenSettings", typeof(MainWindow));

    public static readonly RoutedUICommand OpenXbox =
        new("Open Xbox", "OpenXbox", typeof(MainWindow));

    public static readonly RoutedUICommand RefreshAdaptersCommand =
        new("Refresh", "RefreshAdaptersCommand", typeof(MainWindow));

    public static readonly RoutedUICommand RemoveAtCommand =
        new("Remove", "RemoveAtCommand", typeof(MainWindow));

    // NOTE: SetBackground / ResetBackground / SettingsLoadHandler routed commands
    // were removed in Phase 6 — the content-area Settings page handles those flows
    // directly in Views/SettingsAppearance.xaml.cs (background) and per-toggle
    // save handlers inside each Settings sub-page.

    public static readonly RoutedUICommand TcpProbeCommand =
        new("Probe", "TcpProbeCommand", typeof(MainWindow));

    // ── Phase 7.1 Session 3: context-menu actions ────────────────
    public static readonly RoutedUICommand PacketTestCommand =
        new("Packet Test", "PacketTestCommand", typeof(MainWindow));

    public static readonly RoutedUICommand PortScanCommand =
        new("Port Scan", "PortScanCommand", typeof(MainWindow));

    public static readonly RoutedUICommand GeoIpLookupCommand =
        new("Geo IP Lookup", "GeoIpLookupCommand", typeof(MainWindow));

    public static readonly RoutedUICommand HideIspCommand =
        new("Hide ISP", "HideIspCommand", typeof(MainWindow));

    public static readonly RoutedUICommand ToggleCapture =
        new("Toggle capture", "ToggleCapture", typeof(MainWindow));

    public static readonly RoutedUICommand TogglePanelCommand =
        new("Toggle", "TogglePanelCommand", typeof(MainWindow));

    private readonly DispatcherTimer authTask = new();

    public BitmapImage BackgroundCache;

    private readonly List<int> blacklistedPorts = new();

    private readonly NotifyBindingList<CaptureGrid> dataSource = new();
    private readonly NotifyBindingList<CaptureGrid> gamesDataSource = new();
    private readonly NotifyBindingList<CaptureGrid> partyDataSource = new();
    private int activeTab; // 0=All Traffic, 1=Filtered Traffic

    private readonly TimeSpan lastStatisticsInterval = new(0, 0, 1);

    private readonly object queueLock = new();

    private PacketAnalyserWindow analyserWindow;

    private ConcurrentDictionary<IPAddress, Packet> analyserData = new();

    private ArpDevice arpDevices;

    private Thread arpThread;

    private bool arpThreadStop;

    private bool arpOpenedDevice;

    private PacketArrivalEventHandler arrivalEventHandler;

    private Thread backgroundThread;

    private bool backgroundThreadStop;

    private List<IPAddress> blacklistedAddresses = new();

    private ICaptureStatistics captureStatistics;

    private CaptureStoppedEventHandler captureStoppedEventHandler;

    private bool closeStoryBoardCompleted;

    private object currentView;

    private string currentWallpaper = "None";

    private ICaptureDevice device;

    private List<IPAddress> ipAddresses = new();

    private bool isControlPanelOpen = true;

    private bool isPoisoning;

    private DateTime lastStatisticsOutput;

    private bool isNotificationOpen;

    private bool isNotificationQueued;

    private int packetCount;

    private List<RawCapture> packetQueue = new();

    private Queue<PacketWrapper> packetStrings;

    private bool settingsView;

    private bool statisticsUiNeedsUpdate;

    // PCAP export: store raw captures for .pcap file writing
    private readonly List<RawCapture> pcapBuffer = new();
    private readonly object pcapLock = new();

    // ARP forwarding diagnostic counters — written to %APPDATA%\RhinoSniff\arp-debug.log
    // every 2 seconds while poisoning is active, so we can see exactly where packets go
    private long _fwdSeen;
    private long _fwdIpv4;
    private long _fwdDstIsUs;
    private long _fwdTargetToGw;
    private long _fwdSentTargetToGw;
    private long _fwdGwToTarget;
    private long _fwdSentGwToTarget;
    private long _fwdNoDstTargetMatch;
    private long _fwdSrcNoMatch;
    private long _fwdSendFail;
    private long _fwdQueueDrop;
    private long _ppUpFromTarget;
    private long _ppDownToTarget;
    private System.Threading.Timer _fwdDebugTimer;

    // Async forwarding queue — OnPacketArrival enqueues frames here and returns immediately
    // so the capture callback never blocks on SendPacket. A dedicated worker thread drains
    // the queue and ships frames out via Npcap. This eliminates the lag spike that comes
    // from doing synchronous SendPacket inside OnPacketArrival on bursty game traffic.
    private readonly System.Collections.Concurrent.BlockingCollection<byte[]> _fwdQueue =
        new(new System.Collections.Concurrent.ConcurrentQueue<byte[]>(), 4096);
    private Thread _fwdWorkerThread;
    private volatile bool _fwdWorkerStop;

    // Bandwidth tracking
    private int bandwidthPacketCount;
    private DateTime bandwidthLastReset = DateTime.UtcNow;

    // Live per-IP traffic counters (upload/download per row)
    private readonly ConcurrentDictionary<string, TrafficCounter> trafficCounters = new();
    private readonly DispatcherTimer trafficUpdateTimer = new();

    public MainWindow()
    {
        try
        {
            InitializeComponent();
            Classes.ThemeManager.StampWindowBorder(this);
            Classes.ThemeManager.HookBorderAutoHeal(this);
            Classes.BreathingBorderManager.Register(this);
            // Final deferred stamp at DispatcherPriority.Loaded — this queues the stamp to run
            // AFTER WPF finishes all layout/style/render work on startup, guaranteeing our
            // direct assignment wins the property-precedence race even if a background thread
            // is still resolving styles for the border.
            Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Loaded,
                new Action(() => Classes.ThemeManager.StampWindowBorder(this)));

            MainDataGrid.ItemsSource = dataSource;

            dataSource.AddingNew += DataSource_AddingNew;
            dataSource.RaiseListChangedEvents = true;
            dataSource.ListChanged += DataSource_ListChanged;

            gamesDataSource.RaiseListChangedEvents = true;
            gamesDataSource.ListChanged += DataSource_ListChanged;

            partyDataSource.RaiseListChangedEvents = true;
            partyDataSource.ListChanged += DataSource_ListChanged;
            ResetTitle();

            Title = "RhinoSniff";

            Initialize();

            // Phase 6: SettingsLoadHandler / SetBackground / ResetBackground removed —
            // new content-area Settings pages own their save + background flows directly.
            CommandBindings.Add(new CommandBinding(ExportTheme, ExportThemeEvent));
            CommandBindings.Add(new CommandBinding(ImportTheme, ImportThemeEvent));
            CommandBindings.Add(new CommandBinding(OpenLog, OpenLogEvent));
            CommandBindings.Add(new CommandBinding(ToggleCapture, ToggleCaptureEvent));
            CommandBindings.Add(new CommandBinding(OpenSettings, OpenSettingsEvent));
            CommandBindings.Add(new CommandBinding(HideSideView, HideSideViewEvent));
            CommandBindings.Add(new CommandBinding(HandleCaptions, HandleCaptionsEvent));
            CommandBindings.Add(new CommandBinding(OpenFilters, OpenFiltersEvent));
            CommandBindings.Add(new CommandBinding(OpenAdapter, OpenAdapterEvent));
            CommandBindings.Add(new CommandBinding(OpenArp, OpenArpEvent));
            CommandBindings.Add(new CommandBinding(TogglePanelCommand, TogglePanelEvent));
            CommandBindings.Add(new CommandBinding(CopyCommand, CopyMenuItemEvent));
            CommandBindings.Add(new CommandBinding(LocateCommand, LocateMenuItemEvent));
            CommandBindings.Add(new CommandBinding(TcpProbeCommand, TcpProbeMenuItemEvent));
            CommandBindings.Add(new CommandBinding(ExportCommand, ExportMenuItemEvent));
            CommandBindings.Add(new CommandBinding(ClearAllCommand, ClearAllMenuItemEvent));
            CommandBindings.Add(new CommandBinding(RemoveAtCommand, RemoveAtMenuItemEvent));
            CommandBindings.Add(new CommandBinding(MoveToGamesCommand, MoveToGamesEvent));
            CommandBindings.Add(new CommandBinding(AnalyseCommand, AnalyseMenuItemEvent));

            // Apply saved "All Traffic" tab visibility
            if (!Globals.Settings.ShowOtherInfoTab)
                AllTrafficTab.Visibility = Visibility.Collapsed;
            CommandBindings.Add(new CommandBinding(LabelCommand, AddToLabelsMenuItemEvent));
            CommandBindings.Add(new CommandBinding(RefreshAdaptersCommand, RefreshAdaptersEvent));
            CommandBindings.Add(new CommandBinding(HideNotification, HideNotificationEvent));
            CommandBindings.Add(new CommandBinding(ExportPcapCommand, ExportPcapMenuItemEvent));
            CommandBindings.Add(new CommandBinding(WhoisAllCommand, WhoisAllMenuItemEvent));

            // ── Phase 7.1 Session 3: context-menu nav commands ────────────────
            CommandBindings.Add(new CommandBinding(PacketTestCommand, PacketTestMenuItemEvent));
            CommandBindings.Add(new CommandBinding(PortScanCommand, PortScanMenuItemEvent));
            CommandBindings.Add(new CommandBinding(GeoIpLookupCommand, GeoIpLookupMenuItemEvent));
            CommandBindings.Add(new CommandBinding(HideIspCommand, HideIspMenuItemEvent));

            // ── Phase 5: global hotkeys ────────────────────────────────
            // Manager is created here; bindings are registered from Settings once MainWindow
            // is shown (see Window_Loaded). HotkeyFired routes to FireHotkeyAction on UI thread.
            _hotkeys = new RhinoSniff.Classes.GlobalHotkeyManager();
            _hotkeys.HotkeyFired += action => Dispatcher.BeginInvoke(new Action(() => FireHotkeyAction(action)));
            Loaded += MainWindow_Loaded_Phase5;
            Closed += MainWindow_Closed_Phase5;

            // Load IP Storage (migrates from Settings.Labels on first run; shadow-syncs back)
            _ = RhinoSniff.Classes.IpStorageManager.LoadAsync();
        }
        catch (Exception e)
        {
            _ = e.AutoDumpExceptionAsync();
            Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
            {
                Icon = MsgBox.MsgBoxIcon.Error, Button = MsgBox.MsgBoxBtn.Ok,
                Message = $"{Properties.Resources.GENERIC_EXCEPTION}\n\nWhat happened: {e.Message}"
            });
            Environment.Exit(1);
        }
    }

    public bool IsDialogOpen
    {
        get => (bool) GetValue(IsDialogOpenProperty);
        set => SetValue(IsDialogOpenProperty, value);
    }

    public bool IsSniffing
    {
        get => (bool) GetValue(IsSniffingProperty);
        set => SetValue(IsSniffingProperty, value);
    }

    private void HideNotificationEvent(object sender, ExecutedRoutedEventArgs e)
    {
        var sb = FindResource("CloseNotif") as BeginStoryboard;
        sb?.Storyboard.Begin();
        isNotificationQueued = false;
        isNotificationOpen = false;
    }

    private void AddToLabelsMenuItemEvent(object sender, ExecutedRoutedEventArgs e)
    {
        if (MainDataGrid.SelectedItem is not CaptureGrid dgObj) return;

        TextHost.Text = dgObj.IpAddress.ToString();
        TextLabel.Text = dgObj.Label;
        IsDialogOpen = true;
    }

    // ── Phase 7.1 Session 3: context-menu → tool navigation ───────────────
    // Each handler navigates to the destination tool, then directly calls its
    // PrefillIp method on the cached View instance. (Earlier `Globals.PendingToolPrefillIp`
    // + Loaded-handler approach broke once the View was cached — Loaded only fires once.)

    private void PacketTestMenuItemEvent(object sender, ExecutedRoutedEventArgs e)
    {
        if (MainDataGrid.SelectedItem is not CaptureGrid dgObj || dgObj.IpAddress == null) return;
        var ip = dgObj.IpAddress.ToString();
        ShowPacketTester();
        if (PacketTesterHost.Content is RhinoSniff.Views.PacketTester pt) pt.PrefillIp(ip);
    }

    private void PortScanMenuItemEvent(object sender, ExecutedRoutedEventArgs e)
    {
        if (MainDataGrid.SelectedItem is not CaptureGrid dgObj || dgObj.IpAddress == null) return;
        var ip = dgObj.IpAddress.ToString();
        ShowNmapScanner();
        if (NmapHost.Content is RhinoSniff.Views.NmapScanner ns) ns.PrefillIp(ip);
    }

    private void GeoIpLookupMenuItemEvent(object sender, ExecutedRoutedEventArgs e)
    {
        if (MainDataGrid.SelectedItem is not CaptureGrid dgObj || dgObj.IpAddress == null) return;
        var ip = dgObj.IpAddress.ToString();
        ShowGeoIpLookup();
        if (GeoIpHost.Content is RhinoSniff.Views.GeoIpLookup gi) gi.PrefillIpAndLookup(ip);
    }

    // Dynamic Hide ISP header + enable state when menu opens
    private void MainDataGrid_ContextMenuOpening(object sender, ContextMenuEventArgs e)
    {
        // Sync menu IsEnabled with current settings each time menu opens, so toggling
        // PacketAnalyser / EnableLabels in Settings takes effect without app restart.
        if (AnalyseMenuItem != null)
            AnalyseMenuItem.IsEnabled = Globals.Settings.PacketAnalyser;
        if (AddToLabelsMenuItem != null)
            AddToLabelsMenuItem.IsEnabled = Globals.Settings.EnableLabels;

        if (MainDataGrid.SelectedItem is not CaptureGrid dgObj)
        {
            if (HideIspHeaderText != null) HideIspHeaderText.Text = "Hide ISP";
            if (HideIspMenuItem != null) HideIspMenuItem.IsEnabled = false;
            return;
        }
        var isp = dgObj.Isp;
        var usable = !string.IsNullOrWhiteSpace(isp) && isp != "Failed" && isp != "N/A" && isp != "---";
        if (HideIspHeaderText != null)
            HideIspHeaderText.Text = usable ? $"Hide ISP: {isp}" : "Hide ISP: N/A";
        if (HideIspMenuItem != null)
            HideIspMenuItem.IsEnabled = usable;
    }

    private async void HideIspMenuItemEvent(object sender, ExecutedRoutedEventArgs e)
    {
        if (MainDataGrid.SelectedItem is not CaptureGrid dgObj) return;
        var isp = dgObj.Isp;
        if (string.IsNullOrWhiteSpace(isp) || isp == "Failed" || isp == "N/A" || isp == "---") return;

        // Add to IspFilters denylist if not already present (unified with ISP Filters view)
        var list = Globals.Settings.IspFilters ??= new List<string>();
        if (!list.Any(h => string.Equals(h, isp, StringComparison.OrdinalIgnoreCase)))
            list.Add(isp);

        // Purge currently-showing rows whose ISP matches. Walk from end for safe removal.
        for (int i = dataSource.Count - 1; i >= 0; i--)
        {
            var row = dataSource[i];
            if (!string.IsNullOrEmpty(row.Isp) && row.Isp.Contains(isp, StringComparison.OrdinalIgnoreCase))
                dataSource.RemoveAt(i);
        }
        for (int i = gamesDataSource.Count - 1; i >= 0; i--)
        {
            var row = gamesDataSource[i];
            if (!string.IsNullOrEmpty(row.Isp) && row.Isp.Contains(isp, StringComparison.OrdinalIgnoreCase))
                gamesDataSource.RemoveAt(i);
        }

        try { await Globals.Container.GetInstance<RhinoSniff.Interfaces.IServerSettings>().UpdateSettingsAsync(); }
        catch { }
    }

    private async void AddToSource(CaptureGrid dgObject, bool matchedGameFilter = false)
    {
        try
        {
            if (ipAddresses == null) return;

            // Set FirstSeen timestamp
            dgObject.FirstSeen = DateTime.Now.ToString("HH:mm:ss");
            dgObject.LastSeenTime = DateTime.Now;
            dgObject.LastSeenText = "now";

            // Classify packet type by port
            dgObject.PacketType = ClassifyPacketType(dgObject.Port, dgObject.Protocol);

            // Phase 7.1 Session 4: tag platform from port (ISP not yet known here —
            // re-classified after geo lookup completes, see line ~990).
            dgObject.Platform = ClassifyPlatform(dgObject.Port, null);

            // All Traffic tab ALWAYS gets everything
            if (!ipAddresses.Contains(dgObject.IpAddress))
            {
                ipAddresses.Add(dgObject.IpAddress);
                dataSource.Add(dgObject);

                // Phase 6: cap the number of unique IP rows in memory. When exceeded,
                // prune the oldest (by LastSeenTime) to keep the window bounded.
                var cap = Globals.Settings.MaxPacketsInMemory;
                if (cap > 0 && dataSource.Count > cap)
                {
                    try
                    {
                        var toPrune = dataSource.Count - cap;
                        // Find indices of the oldest N rows (by LastSeenTime ascending).
                        var oldest = dataSource
                            .Select((row, idx) => new { row, idx })
                            .OrderBy(x => x.row.LastSeenTime)
                            .Take(toPrune)
                            .Select(x => new { x.row, x.idx })
                            .ToList();
                        // Remove highest-index first to keep lower indices valid.
                        foreach (var victim in oldest.OrderByDescending(x => x.idx))
                        {
                            try
                            {
                                var ip = victim.row.IpAddress;
                                dataSource.RemoveAt(victim.idx);
                                if (ip != null) ipAddresses.Remove(ip);
                                // Also remove from Filtered view if present.
                                for (int i = gamesDataSource.Count - 1; i >= 0; i--)
                                {
                                    if (gamesDataSource[i].IpAddress?.Equals(ip) == true)
                                    {
                                        gamesDataSource.RemoveAt(i);
                                        break;
                                    }
                                }
                            }
                            catch { /* best-effort */ }
                        }
                    }
                    catch { /* pruning is non-essential — never let it break ingest */ }
                }
            }
            else
            {
                // IP already exists — check if protocol should become BOTH
                for (int i = 0; i < dataSource.Count; i++)
                {
                    if (dataSource[i].IpAddress?.Equals(dgObject.IpAddress) == true)
                    {
                        var existing = dataSource[i];
                        if (existing.Protocol != dgObject.Protocol && existing.Protocol != "BOTH")
                        {
                            existing.Protocol = "BOTH"; // PropertyChanged fires automatically
                        }
                        break;
                    }
                }
            }

            // Filtered Traffic tab ONLY gets packets that matched a game filter
            if (matchedGameFilter)
            {
                if (!gamesDataSource.Any(x => x.IpAddress?.Equals(dgObject.IpAddress) == true))
                    gamesDataSource.Add(dgObject);
            }

            // Sound alert on new connection
            if (Globals.Settings.SoundAlerts)
            {
                try { SystemSounds.Asterisk.Play(); } catch { /* ignore audio errors */ }
            }
        }
        catch (Exception e)
        {
            await e.AutoDumpExceptionAsync();
        }
    }

    private async void AnalyseMenuItemEvent(object sender, ExecutedRoutedEventArgs e)
    {
        if (MainDataGrid.SelectedItem == null || MainDataGrid.SelectedItem is not CaptureGrid selectedItem) return;

        try
        {
            await Dispatcher.InvokeAsync(() =>
            {
                var openDev = GetCurrentCaptureDevice() as NpcapDevice;
                // Only open/close the device if nothing else is holding it. With ARP or Sniff
                // active the device is already open; calling Open() again throws or no-ops, and
                // the finally Close() would tear down the active capture/forward path.
                var weOpened = false;
                try
                {
                    if (openDev != null && !openDev.Opened)
                    {
                        openDev.Open();
                        weOpened = true;
                    }
                    if (!analyserData.TryGetValue(selectedItem.IpAddress, out var analyserPacket)) return;

                    analyserWindow = new PacketAnalyserWindow(analyserPacket,
                        BackgroundCache, GetCurrentCaptureDevice().MacAddress)
                    {
                        Owner = this,
                        Topmost = Globals.Settings.TopMost
                    };
                    DimScreen();
                    analyserWindow.Closed += GenericToolWindow_Closed;
                    analyserWindow.ShowDialog();
                }
                finally
                {
                    if (weOpened && openDev != null && openDev.Opened)
                        openDev.Close();
                }
            });
        }
        catch (Exception er)
        {
            await er.AutoDumpExceptionAsync();
            Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
            {
                Icon = MsgBox.MsgBoxIcon.Error, Button = MsgBox.MsgBoxBtn.Ok,
                Message = $"{Properties.Resources.EXCEPTION_BASIC}\n\nWhat happened: {er.Message}"
            });
        }
    }

    private async void ArpThread()
    {
        try
        {
            IPAddress sourceLocalAddress = null;
            PhysicalAddress sourcePhysicalAddress = null;
            List<RhinoSniff.Models.ArpTarget> targets = null;

            await Dispatcher.InvokeAsync(() =>
            {
                sourceLocalAddress = arpDevices.SourceLocalAddress;
                sourcePhysicalAddress = arpDevices.SourcePhysicalAddress;
                // Snapshot so the loop iterates a stable list even if user edits targets mid-flight
                targets = arpDevices.Targets != null
                    ? new List<RhinoSniff.Models.ArpTarget>(arpDevices.Targets)
                    : new List<RhinoSniff.Models.ArpTarget>();
            });

            while (!arpThreadStop && device != null)
            {
                // 200ms poison interval — 5x per second keeps ARP caches locked in. At 1000ms
                // the gateway's legitimate ARP for the target (once per ~60s) or any other
                // device's ARP request can win the race and un-poison an entry for up to a full
                // second, causing the visible packet-loss / kick symptom. 200ms matches
                // the standard for reliable wireless MITM.
                await Task.Delay(200);
                NpcapDevice currDevice = null;
                await Dispatcher.InvokeAsync(() => { currDevice = (NpcapDevice)GetCurrentCaptureDevice(); });
                if (currDevice == null) continue;

                // Poison every target each cycle. Sequential to avoid hammering the NIC.
                foreach (var t in targets)
                {
                    if (arpThreadStop) break;
                    if (t?.Ip == null || t.Mac == null) continue;
                    try
                    {
                        await currDevice.PoisonAsync(t.Ip, t.Mac, sourceLocalAddress, sourcePhysicalAddress);
                    }
                    catch (Exception innerEx)
                    {
                        // Don't kill the whole thread on one target failing — log + continue
                        await innerEx.AutoDumpExceptionAsync();
                    }
                }
            }
        }
        catch (Exception e)
        {
            await e.AutoDumpExceptionAsync();
            await Dispatcher.InvokeAsync(() =>
            {
                ShowNotification(NotificationType.Alert,
                    "ARP thread has thrown an exception, check the error log for more details");
            });
        }
    }

    private async void BackgroundThread()
    {
        while (!backgroundThreadStop)
        {
            var shouldSleep = true;

            lock (queueLock)
            {
                if (packetQueue.Count != 0) shouldSleep = false;
            }

            if (shouldSleep)
            {
                await Task.Delay(250);
            }
            else
            {
                List<RawCapture> ourQueue;
                lock (queueLock)
                {
                    ourQueue = packetQueue;
                    packetQueue = new List<RawCapture>();
                }

                foreach (var packetWrapper in ourQueue.Select(packet => new PacketWrapper(packetCount, packet)))
                {
                    await Dispatcher.InvokeAsync(() => { packetStrings.Enqueue(packetWrapper); });
                    packetCount++;

                    PacketParser(packetWrapper);
                }

                if (!statisticsUiNeedsUpdate) continue;

                UpdateCaptureStatistics();
                statisticsUiNeedsUpdate = false;
            }
        }
    }

    private void ChangeSideView(Page page, string title)
    {
        currentView = page;
        SideViewFrame.Navigate(page);
        SideViewTitle.Text = title;
    }

    private void ClearAllMenuItemEvent(object sender, ExecutedRoutedEventArgs e)
    {
        if (MainDataGrid.Items.Count <= 0) return;

        ipAddresses = new List<IPAddress>();
        dataSource.Clear();
        gamesDataSource.Clear();
        partyDataSource.Clear();

        // Reset stats
        Interlocked.Exchange(ref totalPacketsSeen, 0);
        Interlocked.Exchange(ref totalBytesSeen, 0);
        Interlocked.Exchange(ref tcpCount, 0);
        Interlocked.Exchange(ref udpCount, 0);
        trafficCounters.Clear();
        UpdateStatsBar();
        UpdateTabBadges();
        UpdateStatusBar();

        ShowNotification(NotificationType.Info, Properties.Resources.UI_CLEAR_SUCCESS);
    }

    private void MoveToGamesEvent(object sender, ExecutedRoutedEventArgs e)
    {
        if (MainDataGrid.SelectedItem is not CaptureGrid selected) return;

        // Don't add duplicates
        var exists = false;
        foreach (CaptureGrid item in gamesDataSource)
        {
            if (item.IpAddress == selected.IpAddress)
            {
                exists = true;
                break;
            }
        }

        if (!exists)
        {
            gamesDataSource.Add(selected);
            ShowNotification(NotificationType.Info, $"Moved {selected.IpAddress} to Filtered Traffic");
        }
    }

    private void CopyMenuItemEvent(object sender, ExecutedRoutedEventArgs e)
    {
        if (MainDataGrid.SelectedItem == null || e.OriginalSource is not DataGridCell dgCell) return;
        
        if (dgCell.Content is ContentPresenter presenter && presenter.Content is CaptureGrid captureGrid)
            captureGrid.IpAddress.ToString().CopyToClipboard();
    }

    private void DataGridView_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        e.Handled = true;
    }

    private void MainDataGrid_MouseDown(object sender, MouseButtonEventArgs e)
    {
        // Deselect when clicking empty area in the DataGrid
        var hit = System.Windows.Media.VisualTreeHelper.HitTest(MainDataGrid, e.GetPosition(MainDataGrid));
        if (hit?.VisualHit != null)
        {
            var row = FindParent<DataGridRow>(hit.VisualHit as System.Windows.DependencyObject);
            if (row == null) MainDataGrid.SelectedItem = null;
        }
    }

    private static T FindParent<T>(System.Windows.DependencyObject child) where T : System.Windows.DependencyObject
    {
        while (child != null)
        {
            if (child is T parent) return parent;
            child = System.Windows.Media.VisualTreeHelper.GetParent(child);
        }
        return null;
    }

    // Stats tracking
    private long totalPacketsSeen;
    private long totalBytesSeen;
    private long tcpCount;
    private long udpCount;

    private void AllTrafficTab_Click(object sender, RoutedEventArgs e)
    {
        SwitchTab(0);
    }

    private void FilteredTrafficTab_Click(object sender, RoutedEventArgs e)
    {
        SwitchTab(1);
    }

    private void FilterSource_Click(object sender, RoutedEventArgs e)
    {
        // Phase 7.1 Session 4: platform classifier wired. Each pill flips the
        // grid to show only rows tagged with that platform (or all if Packet).
        if (sender is not ToggleButton clicked) return;

        // Determine which pill was clicked from x:Name (more reliable than the TextBlock content)
        var newFilter = clicked.Name switch
        {
            "FilterSourcePsn" => RhinoSniff.Models.Platform.Psn,
            "FilterSourceXbox" => RhinoSniff.Models.Platform.Xbox,
            _ => RhinoSniff.Models.Platform.Unknown // FilterSourcePacket = no filter
        };

        _platformFilter = newFilter;

        // Mutually exclusive pill state — only the clicked one stays IsChecked
        FilterSourcePacket.IsChecked = newFilter == RhinoSniff.Models.Platform.Unknown;
        FilterSourcePsn.IsChecked    = newFilter == RhinoSniff.Models.Platform.Psn;
        FilterSourceXbox.IsChecked   = newFilter == RhinoSniff.Models.Platform.Xbox;

        ApplySearchFilter();
        UpdateStatusBar();
    }

    /// <summary>
    /// Switches between All Traffic and Filtered Traffic tabs. Replaces the old
    /// MainTabControl_SelectionChanged logic that was tied to a TabControl.
    /// </summary>
    private void SwitchTab(int index)
    {
        if (MainDataGrid == null) return;
        activeTab = index;

        // Mutually exclusive pill state
        AllTrafficTab.IsChecked = index == 0;
        FilteredTrafficTab.IsChecked = index == 1;
        StyleTabPill(AllTrafficTab, index == 0);
        StyleTabPill(FilteredTrafficTab, index == 1);

        // Show the Filter Source sub-toggles only on Filtered tab
        if (FilteredSubToggles != null)
            FilteredSubToggles.Visibility = index == 1 ? Visibility.Visible : Visibility.Collapsed;

        if (string.IsNullOrEmpty(_lastSearchQuery))
        {
            MainDataGrid.ItemsSource = index == 1 ? (System.Collections.IList)gamesDataSource : dataSource;
        }
        else
        {
            ApplySearchFilter();
        }
        UpdateEmptyStateOverlay();
        UpdateStatusBar();
        UpdateTabBadges();
    }

    private void StyleTabPill(ToggleButton btn, bool active)
    {
        if (btn == null) return;
        btn.Background = active
            ? (System.Windows.Media.Brush)Application.Current.FindResource("AccentTealDark")
            : System.Windows.Media.Brushes.Transparent;
        btn.Foreground = active
            ? (System.Windows.Media.Brush)Application.Current.FindResource("TextOnAccent")
            : (System.Windows.Media.Brush)Application.Current.FindResource("TextMuted");
        btn.BorderBrush = active
            ? (System.Windows.Media.Brush)Application.Current.FindResource("AccentTealDark")
            : (System.Windows.Media.Brush)Application.Current.FindResource("CardBorder");
    }

    /// <summary>
    /// Shows the "No Traffic Data" overlay on the Filtered tab when gamesDataSource is empty.
    /// </summary>
    private void UpdateEmptyStateOverlay()
    {
        if (FilteredEmptyOverlay == null) return;
        FilteredEmptyOverlay.Visibility =
            (activeTab == 1 && gamesDataSource.Count == 0)
                ? Visibility.Visible
                : Visibility.Collapsed;
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        ApplySearchFilter();
        UpdateStatusBar();
    }

    private string _lastSearchQuery = "";

    // Phase 7.1 Session 4: platform-source filter from FilterSource pill row.
    // Unknown = no filter (Packet Filters mode = show everything),
    // Psn / Xbox = show only rows tagged that platform.
    private RhinoSniff.Models.Platform _platformFilter = RhinoSniff.Models.Platform.Unknown;

    private void ApplySearchFilter()
    {
        var query = SearchBox?.Text?.Trim() ?? "";
        _lastSearchQuery = query;

        var sourceList = activeTab switch
        {
            0 => (System.Collections.IList)dataSource,
            1 => (System.Collections.IList)gamesDataSource,
            _ => (System.Collections.IList)dataSource
        };

        var hasSearch = !string.IsNullOrEmpty(query);
        var hasPlatform = _platformFilter != RhinoSniff.Models.Platform.Unknown;

        if (!hasSearch && !hasPlatform)
        {
            MainDataGrid.ItemsSource = sourceList;
        }
        else
        {
            var filtered = new List<CaptureGrid>();
            foreach (CaptureGrid row in sourceList)
            {
                if (hasPlatform && row.Platform != _platformFilter) continue;
                if (hasSearch && !MatchesSearch(row, query)) continue;
                filtered.Add(row);
            }
            MainDataGrid.ItemsSource = filtered;
        }
    }

    private static bool MatchesSearch(CaptureGrid row, string q)
    {
        return (row.IpAddress?.ToString().Contains(q, StringComparison.OrdinalIgnoreCase) == true) ||
               (row.Country?.Contains(q, StringComparison.OrdinalIgnoreCase) == true) ||
               (row.State?.Contains(q, StringComparison.OrdinalIgnoreCase) == true) ||
               (row.City?.Contains(q, StringComparison.OrdinalIgnoreCase) == true) ||
               (row.Isp?.Contains(q, StringComparison.OrdinalIgnoreCase) == true) ||
               (row.Label?.Contains(q, StringComparison.OrdinalIgnoreCase) == true) ||
               (row.Protocol?.Contains(q, StringComparison.OrdinalIgnoreCase) == true) ||
               (row.PacketType?.Contains(q, StringComparison.OrdinalIgnoreCase) == true) ||
               row.Port.ToString().Contains(q);
    }

    private void UpdateStatusBar()
    {
        if (StatusBarText == null) return;
        try
        {
            var total = activeTab switch
            {
                0 => dataSource.Count,
                1 => gamesDataSource.Count,
                _ => 0
            };
            var visible = MainDataGrid?.Items?.Count ?? total;
            var tabName = activeTab switch { 0 => "All Traffic", 1 => "Filtered Traffic", _ => "" };

            if (visible == total || string.IsNullOrEmpty(_lastSearchQuery))
                StatusBarText.Text = $"Showing {total:N0} connections";
            else
                StatusBarText.Text = $"Showing {visible:N0} of {total:N0} connections";

            StatusTabName.Text = tabName;
            StatusCapturedPackets.Text = $"Captured Packets: {Interlocked.Read(ref totalPacketsSeen):N0}";
        }
        catch { StatusBarText.Text = "Ready"; }
    }

    private void UpdateTabBadges()
    {
        try
        {
            // Tab text is static now ("All Traffic" / "Filtered Traffic"); count goes in the
            // separate badge Border/TextBlock. Hides the badge entirely when count is zero.
            if (AllTrafficTabText != null) AllTrafficTabText.Text = "All Traffic";
            if (FilteredTrafficTabText != null) FilteredTrafficTabText.Text = "Filtered Traffic";

            if (AllTrafficTabCount != null)
                AllTrafficTabCount.Text = dataSource.Count.ToString();
            if (AllTrafficTabBadge != null)
                AllTrafficTabBadge.Visibility = dataSource.Count > 0
                    ? System.Windows.Visibility.Visible
                    : System.Windows.Visibility.Collapsed;

            if (FilteredTrafficTabCount != null)
                FilteredTrafficTabCount.Text = gamesDataSource.Count.ToString();
            if (FilteredTrafficTabBadge != null)
                FilteredTrafficTabBadge.Visibility = gamesDataSource.Count > 0
                    ? System.Windows.Visibility.Visible
                    : System.Windows.Visibility.Collapsed;

            UpdateEmptyStateOverlay();
        }
        catch { }
    }

    private void UpdateStatsBar()
    {
        try
        {
            StatsIpCount.Text = $"{dataSource.Count} IPs";
            StatsPacketCount.Text = $"{Interlocked.Read(ref totalPacketsSeen):N0} packets";

            var bytes = Interlocked.Read(ref totalBytesSeen);
            StatsTotalData.Text = bytes < 1024 ? $"{bytes} B"
                : bytes < 1048576 ? $"{bytes / 1024.0:F1} KB"
                : $"{bytes / 1048576.0:F2} MB";

            // Count protocols from actual grid rows (accurate per-IP)
            int tcpRows = 0, udpRows = 0, bothRows = 0;
            for (int i = 0; i < dataSource.Count; i++)
            {
                var p = dataSource[i].Protocol;
                if (p == "TCP") tcpRows++;
                else if (p == "UDP") udpRows++;
                else if (p == "BOTH") bothRows++;
            }

            StatsTcpCount.Text = $"TCP {tcpRows}";
            StatsUdpCount.Text = $"UDP {udpRows}";
            StatsBothCount.Text = $"BOTH {bothRows}";

            // Bottom-right captured packets counter
            StatusCapturedPackets.Text = $"Captured Packets: {Interlocked.Read(ref totalPacketsSeen):N0}";
        }
        catch { }
    }

    private void DataSource_AddingNew(object sender, AddingNewEventArgs e)
    {
        // Geo-lookup is handled in DataSource_ListChanged after the item is actually added.
        // The original code created an empty CaptureGrid here and ran geo on a null IP.
    }

    private async void DataSource_ListChanged(object sender, ListChangedEventArgs e)
    {
        // Refresh search + status on structural changes (new items, deletions, reset)
        // Only update status bar (no list rebuild) on ItemChanged (geo resolves — too frequent to rebuild)
        if (e.ListChangedType == ListChangedType.ItemAdded ||
            e.ListChangedType == ListChangedType.Reset ||
            e.ListChangedType == ListChangedType.ItemDeleted)
        {
            try
            {
                await Dispatcher.InvokeAsync(() =>
                {
                    if (!string.IsNullOrEmpty(_lastSearchQuery))
                        ApplySearchFilter();
                    UpdateStatusBar();
                    UpdateTabBadges();
                    UpdateStatsBar();
                });
            }
            catch { }
        }
        else if (e.ListChangedType == ListChangedType.ItemChanged)
        {
            try { await Dispatcher.InvokeAsync(UpdateStatusBar); } catch { }
        }

        if (e.ListChangedType != ListChangedType.ItemAdded) return;

        try
        {
            var isGeolocationEnabled = Globals.Settings.Geolocate;
            var flag = Globals.Settings.ShowFlags;
            if (!isGeolocationEnabled) return;

            // Use sender to get the correct list — works for dataSource, gamesDataSource, partyDataSource
            if (sender is not NotifyBindingList<CaptureGrid> sourceList) return;
            if (e.NewIndex >= sourceList.Count) return;

            var gridObject = sourceList[e.NewIndex];
            if (gridObject == null || !string.IsNullOrWhiteSpace(gridObject.Country)) return;

            _ = Task.Run(async () =>
            {
                var resp = await Web.IpLocationAsync(gridObject.IpAddress);
                if (resp is null)
                {
                    gridObject.Country = "N/A";
                    gridObject.City = "N/A";
                    gridObject.Isp = "N/A";
                    gridObject.State = "N/A";
                    gridObject.DDoSProtected = PackIconKind.None;
                    gridObject.GeoFailed = true;
                    return;
                }

                if (flag)
                    gridObject.Flag =
                        $"pack://application:,,,/RhinoSniff;Component/Resources/Images/Flags/{resp.Country.Replace(' ', '-')}.png";
                gridObject.Country = resp.Country;
                gridObject.City = resp.City;
                gridObject.Isp = resp.Isp;
                gridObject.State = resp.Region;
                gridObject.DDoSProtected = PackIconKind.None;
                if (resp.IsProxy || resp.IsHosting || resp.IsHotspot)
                    gridObject.DDoSProtected = PackIconKind.LockOutline;

                // Phase 7.1 Session 4: re-classify platform now that ISP is known.
                // Don't downgrade — if port already classified, ISP can only confirm or upgrade Unknown.
                if (gridObject.Platform == RhinoSniff.Models.Platform.Unknown)
                    gridObject.Platform = ClassifyPlatform(gridObject.Port, gridObject.Isp);

                // ── Unified IspFilters denylist with Hide/Dim behavior ──
                // Populated by ISP Filters view (add/remove) AND right-click "Hide ISP: X".
                // Hide = matching ISP is removed from grid. Dim = matching ISP stays but faded.
                var ispRules = Globals.Settings.IspFilters;
                if (ispRules != null && ispRules.Count > 0 && !string.IsNullOrEmpty(gridObject.Isp))
                {
                    var isp = gridObject.Isp;
                    var matches = ispRules.Any(rule =>
                        !string.IsNullOrWhiteSpace(rule) &&
                        isp.Contains(rule, StringComparison.OrdinalIgnoreCase));

                    if (matches)
                    {
                        if (Globals.Settings.IspFilterBehavior == IspFilterBehavior.Hide)
                        {
                            await Dispatcher.InvokeAsync(() =>
                            {
                                var idx = sourceList.IndexOf(gridObject);
                                if (idx >= 0) sourceList.RemoveAt(idx);

                                // Also remove from the other list if present
                                if (sourceList == dataSource)
                                {
                                    var gIdx = gamesDataSource.IndexOf(gridObject);
                                    if (gIdx >= 0) gamesDataSource.RemoveAt(gIdx);
                                }
                                else if (sourceList == gamesDataSource)
                                {
                                    var dIdx = dataSource.IndexOf(gridObject);
                                    if (dIdx >= 0) dataSource.RemoveAt(dIdx);
                                }
                            });
                            return;
                        }
                        // Dim mode: mark row so the grid can style it faded.
                        gridObject.IspDimmed = true;
                    }
                    else
                    {
                        gridObject.IspDimmed = false;
                    }
                }

                // PSN TUNNELED CONNECTION: auto-label Amazon/AWS relay servers
                // Only when party filter is active WITHOUT game filters (to avoid false positives
                // on game servers hosted on AWS like Fortnite/Apex).
                if (string.IsNullOrEmpty(gridObject.Label))
                {
                    var ispLower = (gridObject.Isp ?? "").ToLowerInvariant();
                    if (ispLower.Contains("amazon") || ispLower.Contains("aws") ||
                        ispLower.Contains("microsoft azure") || ispLower.Contains("google cloud"))
                    {
                        var activeFilters = Globals.Settings.ActiveGameFilters;
                        var singleFilter = Globals.Settings.Filter;
                        var hasPsnFilter = singleFilter == FilterPreset.PSNParty ||
                                           (activeFilters != null && activeFilters.Contains(FilterPreset.PSNParty));
                        var hasXboxFilter = singleFilter == FilterPreset.XboxPartyBETA ||
                                            (activeFilters != null && activeFilters.Contains(FilterPreset.XboxPartyBETA));

                        // Count non-party filters to avoid false positives
                        var hasGameFilters = (singleFilter != FilterPreset.None &&
                                              singleFilter != FilterPreset.PSNParty &&
                                              singleFilter != FilterPreset.XboxPartyBETA) ||
                                             (activeFilters != null && activeFilters.Any(f =>
                                                 f != FilterPreset.PSNParty && f != FilterPreset.XboxPartyBETA));

                        if (hasPsnFilter && !hasGameFilters)
                            gridObject.Label = "PSN TUNNELED CONNECTION";
                        else if (hasXboxFilter && !hasGameFilters)
                            gridObject.Label = "XBOX RELAY SERVER";
                        else if (resp.IsHosting && !hasGameFilters)
                            gridObject.Label = "CLOUD/RELAY SERVER";
                    }
                }

                // Properties already fire INotifyPropertyChanged — WPF bindings update automatically
            });
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
            ShowNotification(NotificationType.Error,
                "Something went wrong whilst handling a data source change. It has been written to the log file");
        }
    }

    private async void Device_OnCaptureStopped(object sender, CaptureStoppedEventStatus status)
    {
        if (status == CaptureStoppedEventStatus.CompletedWithoutError) return;

        await Globals.Container.GetInstance<IErrorLogging>().WriteToLogAsync(
            "Capture stop failed with an unhandled exception. SharpPcap did not provide error details.",
            LogLevel.ERROR);
        ShowNotification(NotificationType.Error,
            "Failed to stop capturing. Please close RhinoSniff via Task Manager and restart.");
    }

    // Raw Npcap arrival counters — before ANY code touches them
    private long _rawArrivalCount;
    private long _rawTcpv4Arrival;
    private long _rawUdpv4Arrival;
    private long _rawTcpv6Arrival;
    private long _rawUdpv6Arrival;
    private long _rawOtherv6Arrival;
    private long _rawOtherArrival;
    private long _rawParseFailArrival;

    private static bool MacEquals(byte[] a, byte[] b)
    {
        if (a == null || b == null || a.Length != 6 || b.Length != 6) return false;
        return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] &&
               a[3] == b[3] && a[4] == b[4] && a[5] == b[5];
    }

    private void Device_OnPacketArrival(object sender, CaptureEventArgs e)
    {
        Interlocked.Increment(ref _rawArrivalCount);
        
        // Count raw protocol types at Npcap level
        try
        {
            var rawPkt = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var rawIp = rawPkt?.Extract<IPPacket>();
            if (rawIp == null)
                Interlocked.Increment(ref _rawParseFailArrival);
            else if (rawIp.Version == PacketDotNet.IPVersion.IPv6)
            {
                if (rawIp.Protocol == ProtocolType.Tcp) Interlocked.Increment(ref _rawTcpv6Arrival);
                else if (rawIp.Protocol == ProtocolType.Udp) Interlocked.Increment(ref _rawUdpv6Arrival);
                else Interlocked.Increment(ref _rawOtherv6Arrival);
            }
            else if (rawIp.Protocol == ProtocolType.Tcp)
                Interlocked.Increment(ref _rawTcpv4Arrival);
            else if (rawIp.Protocol == ProtocolType.Udp)
                Interlocked.Increment(ref _rawUdpv4Arrival);
            else
                Interlocked.Increment(ref _rawOtherArrival);
        }
        catch { Interlocked.Increment(ref _rawParseFailArrival); }
        // L2 forwarding — rewrites Ethernet MACs and ships the frame back out the same device.
        // Mirrors alandau/arpspoof (reference Windows ARP spoofer) to ensure proven behavior:
        //   1. Only forward IPv4 frames (ethertype 0x0800). Forwarding ARP/IPv6/etc would loop or
        //      confuse stacks. Games don't use those for P2P traffic anyway.
        //   2. Only forward frames addressed TO OUR MAC. If the dst MAC isn't ours, the frame
        //      was broadcast or destined elsewhere and forwarding it would create loops.
        //   3. Byte-for-byte MAC equality, NOT substring matching. Substring matching on MAC
        //      string reps produced false matches (e.g. two devices sharing a vendor OUI prefix).
        //   4. Rewrite BOTH src and dst MAC — set src to our MAC so the next hop sees a valid
        //      frame from us. Only rewriting dst leaves the original sender's MAC which looks
        //      malformed to game anti-cheat / IDS.
        if (isPoisoning && !arpDevices.IsNullRouted)
        {
            try
            {
                System.Threading.Interlocked.Increment(ref _fwdSeen);
                var pkt = e.Packet.GetPacket();
                var dev = (NpcapDevice) GetCurrentCaptureDevice();
                var ethPkt = pkt?.Extract<EthernetPacket>();
                if (ethPkt != null && dev != null && dev.MacAddress != null)
                {
                    // Only IPv4 — no ARP, IPv6, IPX, etc. (alandau filters to 0x0800 only)
                    if (ethPkt.Type == EthernetType.IPv4)
                    {
                        System.Threading.Interlocked.Increment(ref _fwdIpv4);
                        var srcMacBytes = ethPkt.SourceHardwareAddress?.GetAddressBytes();
                        var dstMacBytes = ethPkt.DestinationHardwareAddress?.GetAddressBytes();
                        var ourMacBytes = dev.MacAddress.GetAddressBytes();

                        // Only forward frames actually addressed to our MAC (dst == us).
                        // If dst is broadcast or anything else, it's not part of the MITM relay.
                        if (dstMacBytes != null && srcMacBytes != null &&
                            MacEquals(dstMacBytes, ourMacBytes) && !MacEquals(srcMacBytes, ourMacBytes))
                        {
                            System.Threading.Interlocked.Increment(ref _fwdDstIsUs);
                            var targets = arpDevices.Targets;
                            var gatewayMac = arpDevices.SourcePhysicalAddress;
                            var gatewayIp = arpDevices.SourceLocalAddress;
                            var ourIp = arpDevices.SourceLocalAddress; // attacker's own IP from ARP setup

                            if (targets != null && targets.Count > 0 && gatewayMac != null)
                            {
                                // CRITICAL: On Wi-Fi the AP rewrites L2 source MAC to its own MAC for
                                // every forwarded frame, regardless of the original sender. So matching
                                // by src MAC NEVER works over Wi-Fi (proven by arp-debug.log analysis:
                                // every "unmatched" packet had the AP's L2 src MAC even when its src IP
                                // was the actual console). We must match by IP instead — the IP layer
                                // is preserved through AP bridging.
                                var ip = pkt.Extract<IPPacket>();
                                if (ip != null)
                                {
                                    var srcIp = ip.SourceAddress;
                                    var dstIp = ip.DestinationAddress;

                                    // (1) target → world: srcIP matches a poisoned target.
                                    //     Rewrite L2 src=ours, dst=gateway, send out.
                                    var srcTarget = targets.FirstOrDefault(t =>
                                        t?.Ip != null && t.Ip.Equals(srcIp));
                                    if (srcTarget != null)
                                    {
                                        System.Threading.Interlocked.Increment(ref _fwdTargetToGw);
                                        ethPkt.SourceHardwareAddress = dev.MacAddress;
                                        ethPkt.DestinationHardwareAddress = gatewayMac;
                                        if (_fwdQueue.TryAdd(ethPkt.Bytes))
                                            System.Threading.Interlocked.Increment(ref _fwdSentTargetToGw);
                                        else
                                            System.Threading.Interlocked.Increment(ref _fwdQueueDrop);
                                    }
                                    else
                                    {
                                        // (2) world → target: dstIP matches a poisoned target.
                                        //     Rewrite L2 src=ours, dst=target's MAC, send to target.
                                        var dstTarget = targets.FirstOrDefault(t =>
                                            t?.Ip != null && t.Ip.Equals(dstIp));
                                        if (dstTarget?.Mac != null)
                                        {
                                            System.Threading.Interlocked.Increment(ref _fwdGwToTarget);
                                            ethPkt.SourceHardwareAddress = dev.MacAddress;
                                            ethPkt.DestinationHardwareAddress = dstTarget.Mac;
                                            if (_fwdQueue.TryAdd(ethPkt.Bytes))
                                                System.Threading.Interlocked.Increment(ref _fwdSentGwToTarget);
                                            else
                                                System.Threading.Interlocked.Increment(ref _fwdQueueDrop);
                                        }
                                        else
                                        {
                                            // Neither src nor dst IP matches a target — not part of our MITM relay.
                                            // Likely OUR PC's own legitimate traffic that happened to come in
                                            // (e.g. our DNS reply, our Discord, etc). Don't forward.
                                            System.Threading.Interlocked.Increment(ref _fwdSrcNoMatch);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch { /* forwarding errors shouldn't crash capture */ }
        }
        var now = DateTime.Now;
        var interval = now - lastStatisticsOutput;
        if (interval > lastStatisticsInterval)
        {
            captureStatistics = e.Device.Statistics;
            statisticsUiNeedsUpdate = true;
            lastStatisticsOutput = now;
        }

        lock (queueLock)
        {
            packetQueue.Add(e.Packet);
        }

        // Store raw capture for PCAP export
        lock (pcapLock)
        {
            pcapBuffer.Add(e.Packet);
        }

        // Bandwidth tracking
        Interlocked.Increment(ref bandwidthPacketCount);
    }

    private async void DialogHost_DialogClosing(object sender, DialogClosingEventArgs eventArgs)
    {
        if (string.IsNullOrWhiteSpace(TextHost.Text) || string.IsNullOrWhiteSpace(TextLabel.Text) ||
            !await TextHost.Text.ValidateIpAsync()) return;
        Globals.Settings.Labels ??= new List<Label>();
        Globals.Settings.Labels.Add(new Label {IpAddress = TextHost.Text, Name = TextLabel.Text});
        var selectedObject = (CaptureGrid) MainDataGrid.SelectedItem;
        selectedObject.Label = TextLabel.Text;
        TextHost.Text = string.Empty;
        TextLabel.Text = string.Empty;
        dataSource[MainDataGrid.SelectedIndex] = selectedObject;
        Dispatcher.Invoke(() => { dataSource.ResetBindings(); });
    }

    private async void ExportMenuItemEvent(object sender, ExecutedRoutedEventArgs e)
    {
        if (MainDataGrid.SelectedItem is not CaptureGrid dgObj) return;

        try
        {
            SaveFileDialog dialog = new()
            {
                Title = "Export capture results...",
                Filter = "Text document (*.txt) | *.txt",
                CheckPathExists = true,
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
            };
            if (dialog.ShowDialog() == true)
            {
                await Globals.Container.GetInstance<IExportDrawer>()
                    .DrawTableForExport(dataSource, dialog.FileName);
                ShowNotification(NotificationType.Info, $"Successfully exported {dataSource.Count} items");
            }
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
            ShowNotification(NotificationType.Error, "Failed to export capture results.");
        }
    }

    private async void ExportThemeEvent(object sender, ExecutedRoutedEventArgs e)
    {
        try
        {
            await Task.Run(async () =>
            {
                SaveFileDialog sfd = new()
                {
                    Filter = "RhinoSniff theme file (*.cst) | *.cst;",
                    Title = "Export theme...",
                    CheckPathExists = true,
                    ValidateNames = true,
                    InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                };
                if (sfd.ShowDialog() == true)
                {
                    await Globals.Container.GetInstance<IThemeUtils>().ExportTheme(sfd.FileName);
                    Dispatcher.Invoke(() =>
                    {
                        Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
                        {
                            Button = MsgBox.MsgBoxBtn.Ok, Icon = MsgBox.MsgBoxIcon.Success,
                            Message = "Your theme has been exported"
                        });
                    });
                }
            });
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
        }
    }

    private ICaptureDevice GetCurrentCaptureDevice()
    {
        ICaptureDevice captureDevice = null;
        Dispatcher.Invoke(() =>
        {
            var adapter = Adapter.Instance.FirstOrDefault(x => x.DisplayName == NetworkAdapterComboBox.Text);
            if (string.IsNullOrEmpty(adapter.Name)) return;
            captureDevice = CaptureDeviceList.Instance.FirstOrDefault(x => x.Name == adapter.Name);
        });
        return captureDevice;
    }

    /// <summary>
    /// BUG #2 (Mullvad / WireGuard traffic gap) — placeholder.
    /// SharpPcap 5.4.0's DeviceModes enum isn't on the public surface where
    /// expected, so the non-promiscuous Open() path is disabled until we
    /// resolve the correct API. For now this matches v1.0.7 behavior
    /// (parameterless Open = default promiscuous).
    /// IsTunnelAdapter() detection retained for the next investigation pass.
    /// </summary>
    private void OpenDeviceTunnelAware(ICaptureDevice dev)
    {
        if (dev == null) return;

        // Default Open() uses a 1000ms read timeout. That means libpcap will hold
        // captured packets in the kernel buffer for up to 1 second before invoking
        // OnPacketArrival. For passive sniffing that's fine, but for MITM L2 forwarding
        // it's catastrophic — at GTA's ~100pps the target's packets pile up for a full
        // second before we forward them, which is well past session timeout and causes
        // an immediate kick. 1ms read timeout makes forwarding effectively wire-speed.
        // Using the legacy Open(DeviceMode, int) overload which is stable in SharpPcap
        // 5.4.0 (the newer DeviceConfiguration path has namespace quirks per prior notes).
        try
        {
            dev.Open(DeviceMode.Promiscuous, 1);
        }
        catch
        {
            // Fallback to default open if the 2-arg overload fails for any reason
            dev.Open();
        }
    }

    private static bool IsTunnelAdapter(string label)
    {
        if (string.IsNullOrWhiteSpace(label)) return false;
        var l = label.ToLowerInvariant();
        return l.Contains("wireguard") || l.Contains("wintun") || l.Contains("mullvad")
            || l.Contains("tap-windows") || l.Contains("tap windows") || l.Contains("openvpn")
            || l.Contains("nordlynx") || l.Contains("protonvpn") || l.Contains("expressvpn")
            || l.Contains("tunnel") || l.Contains("tailscale");
    }

    private void Grid_BeginningEdit(object sender, DataGridBeginningEditEventArgs e)
    {
        e.Cancel = true;
    }

    private async void HandleCaptionsEvent(object sender, ExecutedRoutedEventArgs e)
    {
        try
        {
            if (e.OriginalSource is not Button button) return;

            switch (button.Name)
            {
                case "CloseButton":
                    CloseButton.IsEnabled = false;
                    Close();
                    break;

                case "MinButton":
                    WindowState = WindowState.Minimized;
                    break;

                case "MaxButton":
                    if (WindowState == WindowState.Maximized)
                    {
                        WindowState = WindowState.Normal;
                        MaxIcon.Kind = PackIconKind.WindowMaximize;
                    }
                    else
                    {
                        WindowState = WindowState.Maximized;
                        MaxIcon.Kind = PackIconKind.WindowRestore;
                    }

                    break;
            }
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
        }
    }

    private async void HideSideViewEvent(object sender, ExecutedRoutedEventArgs e)
    {
        try
        {
            CloseSideView.IsEnabled = false;

            // Cancel any running ARP scan
            if (currentView is RhinoSniff.Views.Arp arpPage)
            {
                arpPage.CancelScan();
            }

            // Save settings for any panel that modifies them (Settings, Filters, etc.)
            await Globals.Container.GetInstance<IServerSettings>().UpdateSettingsAsync();

            // Phase 6: the old side-panel Settings page was removed. Theme/background/Topmost
            // are now applied directly by the in-page Settings sub-controls (SettingsAppearance,
            // SettingsGeneral). No on-close reload needed here.

            // Let the ORIGINAL animation chain handle the close:
            // HideDim plays → Storyboard_Completed fires → CloseSettings + TogglePanel
            MaxBottom.IsEnabled = true;
            var hideDim = FindResource("HideDim") as BeginStoryboard;
            hideDim?.Storyboard.Begin();
            await Task.Delay(400);
            CloseSideView.IsEnabled = true;
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
        }
    }

    private void IconBox_MouseDown(object sender, MouseButtonEventArgs e)
    {
        Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
        {
            Icon = MsgBox.MsgBoxIcon.Information, Button = MsgBox.MsgBoxBtn.Ok,
            Message = Properties.Resources.UI_ABOUT_BOX
        });
    }

    private async void ImportThemeEvent(object sender, ExecutedRoutedEventArgs e)
    {
        try
        {
            await Task.Run(async () =>
            {
                OpenFileDialog openFileDialog = new()
                {
                    Filter = "Theme files (*.cst) | *.cst;",
                    Title = "Select theme file...",
                    CheckFileExists = true,
                    CheckPathExists = true,
                    ReadOnlyChecked = true,
                    ValidateNames = true,
                    InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    Multiselect = false
                };
                if (openFileDialog.ShowDialog() == true)
                {
                    await Globals.Container.GetInstance<IThemeUtils>().ImportTheme(openFileDialog.FileName);
                    Border.BorderBrush =
                        new SolidColorBrush(
                            SafeParseColor(Globals.Settings.HexColor));
                    if (Globals.Settings.Background != "None")
                        LoadBackground(Globals.Settings.Background);

                    Dispatcher.Invoke(() =>
                    {
                        Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
                        {
                            Button = MsgBox.MsgBoxBtn.Ok, Message = "Imported theme successfully",
                            Icon = MsgBox.MsgBoxIcon.Success
                        });
                    });
                }
            });
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
        }
    }

    private async void InitAdapters()
    {
        try
        {
            await Dispatcher.InvokeAsync(() =>
            {
                NetworkAdapterComboBox.ItemsSource = Adapter.Instance.Select(x => x.DisplayName);
                if (string.IsNullOrWhiteSpace(Globals.Settings.InterfaceName)) return;
                var saved = Adapter.Instance.FirstOrDefault(x => x.Name == Globals.Settings.InterfaceName);
                if (!string.IsNullOrEmpty(saved.DisplayName))
                    NetworkAdapterComboBox.SelectedItem = saved.DisplayName;
            });
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
            ShowNotification(NotificationType.Error, Properties.Resources.ADAPTER_EXCEPTION);
        }
    }

    private void Initialize()
    {
        Topmost = false;
        BackgroundCache = new BitmapImage();
        StateChanged += MainWindow_StateChanged;
        MaxHeight = SystemParameters.MaximizedPrimaryScreenHeight;
        MaxWidth = SystemParameters.MaximizedPrimaryScreenWidth;
        MainDataGrid.IsSynchronizedWithCurrentItem = true;
        MaxBottom.IsEnabled = false;

        if (Globals.Settings.DiscordStatus)
        {
            var rpc = Globals.Container.GetInstance<IDiscordPresenceService>();
            rpc.Initialize();
            // Default presence already says "Ready to capture" — no need to override
        }

        if (!Globals.Settings.HardwareAccel)
            RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
        if (!Globals.Settings.PacketAnalyser)
            AnalyseMenuItem.IsEnabled = false;
        if (!Globals.Settings.EnableLabels)
            AddToLabelsMenuItem.IsEnabled = false;
        if (Globals.Settings.TopMost) Topmost = true;

        // Restore persisted sidebar collapsed state (Phase 1)
        if (Globals.Settings.SidebarCollapsed) ApplySidebarCollapsed(true);
        if (Globals.Settings.ColorType != ColorType.Default)
            try
            {
                Globals.Container.GetInstance<IThemeUtils>().SwitchTheme(new Theme
                {
                    DarkMode = Globals.Settings.DarkMode, PrimaryColor = Globals.Settings.ColorType,
                    SecondaryColor = Globals.Settings.ColorType,
                    CustomColorBrush =
                        SafeParseColor(Globals.Settings.HexColor)
                });
            }
            catch (Exception ex)
            {
                ex.AutoDumpExceptionAsync()
                    .GetAwaiter()
                    .GetResult();
                ShowNotification(NotificationType.Error, Properties.Resources.THEME_APPLY_EXCEPTION);
            }

        if (Globals.Settings.Background != "None")
        {
            Globals.Settings.Background = Globals.Settings.Background.Replace('/', '\\');
            if (!LoadBackground(Globals.Settings.Background))
                ShowNotification(NotificationType.Error, Properties.Resources.BACKGROUND_LOAD_EXCEPTION);
        }

        InitAdapters();
        MaxBottom.IsEnabled = true;
        if (!Globals.Settings.AutoShowPanel) TogglePanel();

        // Live traffic counter UI refresh (500ms = smooth without CPU waste)
        trafficUpdateTimer.Interval = TimeSpan.FromMilliseconds(250);
        trafficUpdateTimer.Tick += TrafficUpdateTimer_Tick;

        Activated += Window_Activated;
        Deactivated += Window_Deactivated;
    }

    private void DimScreen()
    {
        Dimmer.Visibility = Visibility.Visible;
        var dimScreen = FindResource("Dim") as BeginStoryboard;
        dimScreen?.Storyboard.Begin();
    }

    // ── Phase 8: Traffic Control modal hosting ────────────────────────────
    // The TC wizard runs as an inline UserControl overlay (not a separate Window)
    // so it resizes with the parent and click-outside dismisses it cleanly.

    private RhinoSniff.Windows.TrafficRuleWizard _activeTcWizard;
    private Action<RhinoSniff.Models.TrafficRule> _tcWizardCallback;

    /// <summary>
    /// Shows the Traffic Control wizard as a modal overlay over MainWindow.
    /// <paramref name="editRule"/> non-null = edit mode (pre-fills wizard).
    /// <paramref name="onComplete"/> fires when the wizard finishes — non-null
    /// rule = created/edited, null = dismissed.
    /// </summary>
    public void ShowTrafficRuleWizard(RhinoSniff.Models.TrafficRule editRule,
        Action<RhinoSniff.Models.TrafficRule> onComplete)
    {
        // If one is already up, dismiss it first
        CloseTcWizard(null);

        _tcWizardCallback = onComplete;
        _activeTcWizard = new RhinoSniff.Windows.TrafficRuleWizard(editRule);
        _activeTcWizard.Completed += TcWizard_Completed;
        TcModalHost.Content = _activeTcWizard;
        TcModalRoot.Visibility = Visibility.Visible;
    }

    private void TcWizard_Completed(object sender, EventArgs e)
    {
        var rule = _activeTcWizard?.CreatedRule;
        CloseTcWizard(rule);
    }

    private void TcModalBackdrop_MouseDown(object sender, MouseButtonEventArgs e)
    {
        // Click-outside dismisses the wizard (no save)
        CloseTcWizard(null);
    }

    private void CloseTcWizard(RhinoSniff.Models.TrafficRule result)
    {
        if (_activeTcWizard != null)
        {
            _activeTcWizard.Completed -= TcWizard_Completed;
            _activeTcWizard = null;
        }
        TcModalHost.Content = null;
        TcModalRoot.Visibility = Visibility.Collapsed;

        var cb = _tcWizardCallback;
        _tcWizardCallback = null;
        try { cb?.Invoke(result); } catch { }
    }

    // ── Phase 9: Create Filter wizard overlay (mirror of the TC wizard host) ──
    private RhinoSniff.Windows.CreateFilterWizard _activeFilterWizard;
    private Action<RhinoSniff.Models.UserFilter> _filterWizardCallback;

    /// <summary>
    /// Shows the Create Packet Filter wizard overlay. <paramref name="editExisting"/>
    /// non-null = edit mode (prefill + skip source chooser). <paramref name="onComplete"/>
    /// fires with the finished UserFilter, or null on dismiss.
    /// </summary>
    public void ShowCreateFilterWizard(RhinoSniff.Models.UserFilter editExisting,
        Action<RhinoSniff.Models.UserFilter> onComplete)
    {
        CloseFilterWizard(null);

        _filterWizardCallback = onComplete;
        _activeFilterWizard = new RhinoSniff.Windows.CreateFilterWizard(editExisting);
        _activeFilterWizard.Completed += FilterWizard_Completed;
        _activeFilterWizard.Cancelled += FilterWizard_Cancelled;
        FilterModalHost.Content = _activeFilterWizard;
        FilterModalRoot.Visibility = Visibility.Visible;
    }

    private void FilterWizard_Completed(object sender, EventArgs e)
    {
        var filter = _activeFilterWizard?.CreatedFilter;
        CloseFilterWizard(filter);
    }

    private void FilterWizard_Cancelled(object sender, EventArgs e) => CloseFilterWizard(null);

    private void FilterModalBackdrop_MouseDown(object sender, MouseButtonEventArgs e)
    {
        // Click-outside dismisses whichever filter modal is open (no save).
        if (_activeFilterWizard != null) CloseFilterWizard(null);
        else if (_activeFilterDialog != null) CloseFilterActionDialog(null);
    }

    private void CloseFilterWizard(RhinoSniff.Models.UserFilter result)
    {
        if (_activeFilterWizard != null)
        {
            _activeFilterWizard.Completed -= FilterWizard_Completed;
            _activeFilterWizard.Cancelled -= FilterWizard_Cancelled;
            _activeFilterWizard = null;
        }
        // Only hide the host/root if no dialog is taking over
        if (_activeFilterDialog == null)
        {
            FilterModalHost.Content = null;
            FilterModalRoot.Visibility = Visibility.Collapsed;
        }

        var cb = _filterWizardCallback;
        _filterWizardCallback = null;
        try { cb?.Invoke(result); } catch { }
    }

    // ═══ Filter action dialog (Highlight/Discard/Remove) ═══════════════════
    // Hosted in the same FilterModalRoot overlay as CreateFilterWizard — so it
    // darkens the full main window and supports click-outside-to-close, matching
    // the TrafficRuleWizard pattern. Replaces the old page-scoped DialogHost which
    // only dimmed the PacketFilters page area (not sidebar / titlebar).
    private RhinoSniff.Windows.FilterActionDialog _activeFilterDialog;
    private Action<object> _filterDialogCallback;

    /// <summary>
    /// Shows the Highlight/Discard/Remove dialog as a main-window-level modal.
    /// </summary>
    /// <param name="title">Header title (usually the filter name).</param>
    /// <param name="isActive">True if filter is currently enabled — shows the red Remove button.</param>
    /// <param name="currentAction">Pre-selected action.</param>
    /// <param name="onComplete">Callback: receives FilterAction on Apply, "remove" string on Remove, null on cancel.</param>
    public void ShowFilterActionDialog(string title, bool isActive,
        RhinoSniff.Models.FilterAction currentAction, Action<object> onComplete)
    {
        CloseFilterActionDialog(null);

        _filterDialogCallback = onComplete;
        _activeFilterDialog = new RhinoSniff.Windows.FilterActionDialog(title, isActive, currentAction);
        _activeFilterDialog.Completed += FilterDialog_Completed;
        _activeFilterDialog.Cancelled += FilterDialog_Cancelled;
        FilterModalHost.Content = _activeFilterDialog;
        FilterModalRoot.Visibility = Visibility.Visible;
    }

    private void FilterDialog_Completed(object sender, EventArgs e)
    {
        var result = _activeFilterDialog?.Result;
        CloseFilterActionDialog(result);
    }

    private void FilterDialog_Cancelled(object sender, EventArgs e) => CloseFilterActionDialog(null);

    private void CloseFilterActionDialog(object result)
    {
        if (_activeFilterDialog != null)
        {
            _activeFilterDialog.Completed -= FilterDialog_Completed;
            _activeFilterDialog.Cancelled -= FilterDialog_Cancelled;
            _activeFilterDialog = null;
        }
        // Only hide the host/root if no wizard is taking over
        if (_activeFilterWizard == null)
        {
            FilterModalHost.Content = null;
            FilterModalRoot.Visibility = Visibility.Collapsed;
        }

        var cb = _filterDialogCallback;
        _filterDialogCallback = null;
        try { cb?.Invoke(result); } catch { }
    }

    /// <summary>
    /// Toggles the green "running" dot on the Traffic Control sidebar button.
    /// Called by the TrafficControl view when its engine starts/stops.
    /// </summary>
    public void SetTrafficControlRunningIndicator(bool running)
    {
        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.BeginInvoke(new Action(() => SetTrafficControlRunningIndicator(running)));
            return;
        }
        if (NavTcRunningDot != null)
            NavTcRunningDot.Visibility = running ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <summary>
    /// Safely loads a background image from a local file path.
    /// Validates the path is a real local file (blocks UNC paths, remote URIs, etc).
    /// Handles both static images and animated GIFs.
    /// </summary>
    private bool LoadBackground(string path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path) || path == "None") return false;

            // SECURITY: Only allow local file paths, block UNC/HTTP/remote URIs
            var fullPath = Path.GetFullPath(path);
            if (!File.Exists(fullPath)) return false;
            var uri = new Uri(fullPath);
            if (!uri.IsFile || uri.IsUnc) return false;

            BackgroundCache = null;
            GC.Collect();
            BackgroundCache = new BitmapImage();
            BackgroundCache.BeginInit();
            BackgroundCache.UriSource = uri;
            BackgroundCache.EndInit();
            BackgroundImage.Source = BackgroundCache;
            currentWallpaper = fullPath;

            SetPanelTransparency(true);

            if (fullPath.EndsWith(".gif", StringComparison.OrdinalIgnoreCase))
                ImageBehavior.SetAnimatedSource(BackgroundImage, BackgroundCache);

            return true;
        }
        catch (Exception ex)
        {
            _ = ex.AutoDumpExceptionAsync();
            return false;
        }
    }

    private void ClearBackground()
    {
        BackgroundCache = new BitmapImage();
        BackgroundImage.Source = null;
        currentWallpaper = "None";
        SetPanelTransparency(false);
    }

    private void SetPanelTransparency(bool transparent)
    {
        // Uses SetResourceReference so colors track live theme changes (Dark/Light).
        // Alpha variants are used when a wallpaper is showing behind panels.
        if (transparent)
        {
            var t = System.Windows.Media.Colors.Transparent;
            SidebarBorder.SetResourceReference(Border.BackgroundProperty, "SidebarBgAlpha");
            SidebarAdapterBorder.SetResourceReference(Border.BackgroundProperty, "SidebarAdapterBgAlpha");
            TopBox.SetResourceReference(Panel.BackgroundProperty, "TopBoxBgAlpha");
            StatsBarBorder.SetResourceReference(Border.BackgroundProperty, "StatsBarBgAlpha");
            SearchBarBorder.SetResourceReference(Border.BackgroundProperty, "SearchBarBgAlpha");
            SearchBox.SetResourceReference(Control.BackgroundProperty, "SearchBoxBgAlpha");
            MainDataGrid.Background = new SolidColorBrush(t);
            MainDataGrid.SetResourceReference(DataGrid.RowBackgroundProperty, "GridRowAltAlpha");
            BottomStatusBorder.SetResourceReference(Border.BackgroundProperty, "BottomStatusBgAlpha");
        }
        else
        {
            SidebarBorder.SetResourceReference(Border.BackgroundProperty, "SidebarBg");
            SidebarAdapterBorder.SetResourceReference(Border.BackgroundProperty, "SidebarAdapterBg");
            TopBox.SetResourceReference(Panel.BackgroundProperty, "TopBoxBg");
            StatsBarBorder.SetResourceReference(Border.BackgroundProperty, "StatsBarBg");
            SearchBarBorder.SetResourceReference(Border.BackgroundProperty, "SearchBarBg");
            SearchBox.SetResourceReference(Control.BackgroundProperty, "SearchBoxBg");
            MainDataGrid.SetResourceReference(Control.BackgroundProperty, "GridBg");
            MainDataGrid.RowBackground = null;
            BottomStatusBorder.SetResourceReference(Border.BackgroundProperty, "BottomStatusBg");
        }
    }

    private void LocateMenuItemEvent(object sender, ExecutedRoutedEventArgs e)
    {
        if (MainDataGrid.SelectedItem is not CaptureGrid dgObj) return;

        ChangeSideView(new Locate(dgObj.IpAddress), "Locate host");
        TogglePanel(true);
        MaxBottom.IsEnabled = false;
        Dimmer.Visibility = Visibility.Visible;
        var dimScreen = FindResource("Dim") as BeginStoryboard;
        dimScreen?.Storyboard.Begin();
        var showSettings = FindResource("OpenSettings") as BeginStoryboard;
        showSettings?.Storyboard.Begin();
        settingsView = true;
    }

    private void MainWindow_StateChanged(object sender, EventArgs e)
    {
        MaxIcon.Kind = WindowState == WindowState.Maximized ? PackIconKind.WindowRestore : PackIconKind.WindowMaximize;
        // (Accent border re-stamping is handled globally by ThemeManager.HookBorderAutoHeal.)
    }

    private async void NetworkAdapterComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (e.AddedItems.Count == 0) return;
        var selected = e.AddedItems.Cast<string>().FirstOrDefault();
        if (string.IsNullOrEmpty(selected)) return;
        var adapter = Adapter.Instance.FirstOrDefault(x => x.DisplayName == selected);
        if (string.IsNullOrEmpty(adapter.Name)) return;
        Globals.Settings.InterfaceName = adapter.Name;
        await Globals.Container.GetInstance<IServerSettings>().UpdateSettingsAsync();

        // Update sidebar adapter indicator
        SidebarAdapterText.Text = selected;
    }

    /// <summary>
    /// Opens a page in the side panel. If panel is already open, swaps content.
    /// Checks actual Dimmer visibility instead of trusting settingsView flag.
    /// </summary>
    private async void OpenSidePanel(Page content, string title)
    {
        try
        {
            // If panel is actually visible, just swap content
            if (Dimmer.Visibility == Visibility.Visible && settingsView)
            {
                ChangeSideView(content, title);
                return;
            }

            // Panel not open — full animation
            settingsView = false; // Reset in case it was stuck
            TogglePanel(true);
            ChangeSideView(content, title);
            MaxBottom.IsEnabled = false;
            Dimmer.Visibility = Visibility.Visible;
            var dimScreen = FindResource("Dim") as BeginStoryboard;
            dimScreen?.Storyboard.Begin();
            var showSettings = FindResource("OpenSettings") as BeginStoryboard;
            showSettings?.Storyboard.Begin();
            settingsView = true;
            await Task.Delay(400);
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
        }
    }

    private void OpenAdapterEvent(object sender, ExecutedRoutedEventArgs e)
    {
        if (NetworkAdapterComboBox.SelectedItem == null)
        {
            ShowNotification(NotificationType.Info, "Please select a network adapter first.");
            return;
        }
        var item = Adapter.Instance.FirstOrDefault(x => x.DisplayName == NetworkAdapterComboBox.Text);
        if (string.IsNullOrEmpty(item.Name)) return;
        OpenSidePanel(new AdapterInfo(item), "Adapter Info");
    }

    private void OpenArpEvent(object sender, ExecutedRoutedEventArgs e)
    {
        if (NetworkAdapterComboBox.SelectedItem == null)
        {
            ShowNotification(NotificationType.Info, "Please select a network adapter first.");
            return;
        }
        var capDevice = (NpcapDevice) GetCurrentCaptureDevice();
        if (capDevice.GetAddressFamily() == AddressFamily.IPv6)
        {
            ShowNotification(NotificationType.Alert, "You must disable IPv6 to use ARP poisoning");
            return;
        }
        if (capDevice.GetAddressFamily() == AddressFamily.Null)
        {
            ShowNotification(NotificationType.Alert, "This adapter does not have a valid IP address.");
            return;
        }
        OpenSidePanel(new RhinoSniff.Views.Arp(this, capDevice), "ARP Setup");
    }

    // ═══ ARP PUBLIC API (called by Arp wizard page) ═══

    public bool IsPoisoningPublic => isPoisoning;

    public void SetAllTrafficTabVisibility(bool show)
    {
        AllTrafficTab.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
        // If hiding and currently selected, switch to Filtered Traffic
        if (!show && activeTab == 0) SwitchTab(1);
    }

    public ArpDevice GetArpDevices() => arpDevices;

    public void SetArpDevices(ArpDevice devices)
    {
        arpDevices = devices;
        // Show the Start/Stop ARP button in main toolbar once configured
        Dispatcher.Invoke(() =>
        {
            ArpToggleButton.Visibility = Visibility.Visible;
        });
    }

    private void ArpToggleButton_Click(object sender, RoutedEventArgs e)
    {
        if (isPoisoning)
        {
            StopArpPoisoning();
            ArpToggleText.Text = "START ARP";
            ArpToggleIcon.Kind = PackIconKind.Play;
            ArpToggleButton.SetResourceReference(System.Windows.Controls.Control.BackgroundProperty, "ToolbarBtnIdleBg");
        }
        else
        {
            if (!StartArpPoisoning())
            {
                ShowNotification(NotificationType.Error, "ARP: Configure ARP settings first (Setup ARP button).");
                return;
            }
            ArpToggleText.Text = "STOP ARP";
            ArpToggleIcon.Kind = PackIconKind.Stop;
            ArpToggleButton.SetResourceReference(System.Windows.Controls.Control.BackgroundProperty, "ToolbarBtnDangerBg");
        }
    }

    /// <summary>
    /// Syncs the main toolbar ARP button state (called by Arp wizard page)
    /// </summary>
    public void SyncArpToolbarState()
    {
        Dispatcher.Invoke(() =>
        {
            if (isPoisoning)
            {
                ArpToggleButton.Visibility = Visibility.Visible;
                ArpToggleText.Text = "STOP ARP";
                ArpToggleIcon.Kind = PackIconKind.Stop;
                ArpToggleButton.SetResourceReference(System.Windows.Controls.Control.BackgroundProperty, "ToolbarBtnDangerBg");
            }
            else if (arpDevices.SourceLocalAddress != null)
            {
                ArpToggleButton.Visibility = Visibility.Visible;
                ArpToggleText.Text = "START ARP";
                ArpToggleIcon.Kind = PackIconKind.Play;
                ArpToggleButton.SetResourceReference(System.Windows.Controls.Control.BackgroundProperty, "ToolbarBtnIdleBg");
            }
        });
    }

    public bool StartArpPoisoning()
    {
        // Multi-target validation (v2.9.0): need source + at least one target.
        // Back-compat: if legacy single-target fields are set but Targets is empty,
        // synthesise a single-element Targets list from them.
        if (arpDevices.SourceLocalAddress == null || arpDevices.SourcePhysicalAddress == null)
            return false;

        var hasMulti = arpDevices.Targets != null && arpDevices.Targets.Count > 0;
        var hasLegacy = arpDevices.TargetLocalAddress != null && arpDevices.TargetPhysicalAddress != null;
        if (!hasMulti && !hasLegacy) return false;

        if (!hasMulti && hasLegacy)
        {
            arpDevices = new ArpDevice
            {
                IsNullRouted = arpDevices.IsNullRouted,
                SourceLocalAddress = arpDevices.SourceLocalAddress,
                SourcePhysicalAddress = arpDevices.SourcePhysicalAddress,
                TargetLocalAddress = arpDevices.TargetLocalAddress,
                TargetPhysicalAddress = arpDevices.TargetPhysicalAddress,
                Targets = new List<RhinoSniff.Models.ArpTarget>
                {
                    new() { Ip = arpDevices.TargetLocalAddress, Mac = arpDevices.TargetPhysicalAddress }
                }
            };
        }

        isPoisoning = true;

        // NOTE: we deliberately do NOT enable Windows kernel IP forwarding (IPEnableRouter +
        // netsh + RemoteAccess). Windows routing through the IP layer is unreliable for MITM
        // (firewall drops, NAT rewriting, anti-cheat flags on modified source addresses) and
        // it's not needed — we forward at Layer 2 via Npcap in Device_OnPacketArrival, which
        // is how every working Windows ARP spoofer does it (see alandau/arpspoof source).

        // Flow: Start ARP can happen BEFORE Start Sniff.
        // We need the device open AND capturing so OnPacketArrival fires (that's where the
        // forwarding logic lives — rewriting dst MAC and re-sending via Npcap, which is how
        // Windows MITM actually works since Windows IP routing isn't reliable for this).
        if (!IsSniffing)
        {
            try
            {
                device = GetCurrentCaptureDevice();
                OpenDeviceTunnelAware(device);
                // Subscribe to arrivals + start capture so Device_OnPacketArrival fires and
                // our L2 forwarding block routes target↔gateway packets. Without this, opening
                // the device alone doesn't deliver packets — target's outbound traffic arrives
                // at our NIC, Npcap has it queued, but nobody reads it, so it piles up and
                // the target's session dies.
                device.OnPacketArrival += Device_OnPacketArrival;
                device.StartCapture();
                arpOpenedDevice = true; // Track that WE opened it for ARP
            }
            catch (Exception ex)
            {
                _ = ex.AutoDumpExceptionAsync();
                isPoisoning = false;
                return false;
            }
        }

        if (arpThread == null || !arpThread.IsAlive)
        {
            arpThreadStop = false;
            arpThread = new Thread(ArpThread)
            {
                Name = "RhinoSniff-ARP-Thread",
                IsBackground = true,
                Priority = ThreadPriority.BelowNormal
            };
            arpThread.Start();
        }

        // Start the forwarding worker thread — drains the forwarding queue and ships
        // frames out via SendPacket. Runs at AboveNormal priority so forwarding never
        // starves under UI load.
        if (_fwdWorkerThread == null || !_fwdWorkerThread.IsAlive)
        {
            _fwdWorkerStop = false;
            _fwdWorkerThread = new Thread(() =>
            {
                try
                {
                    while (!_fwdWorkerStop)
                    {
                        byte[] frame = null;
                        try
                        {
                            if (!_fwdQueue.TryTake(out frame, 100)) continue;
                        }
                        catch { continue; }
                        if (frame == null) continue;
                        try
                        {
                            var d = GetCurrentCaptureDevice() as NpcapDevice;
                            if (d != null && d.Opened) d.SendPacket(frame);
                        }
                        catch { System.Threading.Interlocked.Increment(ref _fwdSendFail); }
                    }
                }
                catch { }
            })
            {
                Name = "RhinoSniff-Forward-Worker",
                IsBackground = true,
                Priority = ThreadPriority.AboveNormal
            };
            _fwdWorkerThread.Start();
        }

        // Reset counters and start 2-second debug log dump so we can see forwarding state
        System.Threading.Interlocked.Exchange(ref _fwdSeen, 0);
        System.Threading.Interlocked.Exchange(ref _fwdIpv4, 0);
        System.Threading.Interlocked.Exchange(ref _fwdDstIsUs, 0);
        System.Threading.Interlocked.Exchange(ref _fwdTargetToGw, 0);
        System.Threading.Interlocked.Exchange(ref _fwdSentTargetToGw, 0);
        System.Threading.Interlocked.Exchange(ref _fwdGwToTarget, 0);
        System.Threading.Interlocked.Exchange(ref _fwdSentGwToTarget, 0);
        System.Threading.Interlocked.Exchange(ref _fwdNoDstTargetMatch, 0);
        System.Threading.Interlocked.Exchange(ref _fwdSrcNoMatch, 0);
        System.Threading.Interlocked.Exchange(ref _fwdSendFail, 0);
        System.Threading.Interlocked.Exchange(ref _ppUpFromTarget, 0);
        System.Threading.Interlocked.Exchange(ref _ppDownToTarget, 0);
        _fwdDebugTimer?.Dispose();
        _fwdDebugTimer = new System.Threading.Timer(_ =>
        {
            try
            {
                var dir = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RhinoSniff");
                System.IO.Directory.CreateDirectory(dir);
                var path = System.IO.Path.Combine(dir, "arp-debug.log");
                var line = $"[{DateTime.Now:HH:mm:ss}] seen={_fwdSeen} ipv4={_fwdIpv4} dstIsUs={_fwdDstIsUs} " +
                           $"t2g={_fwdTargetToGw}(sent={_fwdSentTargetToGw}) g2t={_fwdGwToTarget}(sent={_fwdSentGwToTarget}) " +
                           $"noDstTargetMatch={_fwdNoDstTargetMatch} srcNoMatch={_fwdSrcNoMatch} sendFail={_fwdSendFail} qDrop={_fwdQueueDrop} qDepth={_fwdQueue.Count} " +
                           $"PP_UpFromTgt={_ppUpFromTarget} PP_DownToTgt={_ppDownToTarget}\n";
                System.IO.File.AppendAllText(path, line);
            }
            catch { }
        }, null, 2000, 2000);

        return true;
    }

    public void StopArpPoisoning()
    {
        isPoisoning = false;
        arpThreadStop = true;
        _fwdWorkerStop = true;
        // Drain any remaining queued frames so they don't pile up between sessions
        while (_fwdQueue.TryTake(out _, 0)) { }
        _fwdDebugTimer?.Dispose();
        _fwdDebugTimer = null;
        if (arpThread != null && arpThread.IsAlive)
        {
            // Fire-and-forget join on a background task so UI doesn't block for up to 2s
            var threadToJoin = arpThread;
            _ = Task.Run(() =>
            {
                try { threadToJoin.Join(2000); } catch { }
            });
        }

        // RESTORE correct ARP mappings before closing the device. Run as fire-and-forget
        // background task so the UI doesn't freeze for ~150ms per target. The restore still
        // completes in ~150ms total, just without blocking the UI thread.
        var snapshotTargets = arpDevices.Targets?.ToList();
        var snapshotSourceIp = arpDevices.SourceLocalAddress;
        var snapshotSourceMac = arpDevices.SourcePhysicalAddress;
        var snapshotDevice = device as NpcapDevice;
        _ = Task.Run(async () =>
        {
            try
            {
                if (snapshotDevice != null && snapshotTargets != null &&
                    snapshotSourceIp != null && snapshotSourceMac != null)
                {
                    foreach (var t in snapshotTargets)
                    {
                        if (t?.Ip == null || t.Mac == null) continue;
                        try
                        {
                            await snapshotDevice.RestoreAsync(t.Ip, t.Mac,
                                snapshotSourceIp, snapshotSourceMac);
                        }
                        catch { }
                    }
                }
            }
            catch { }
        });

        // If WE opened the device for ARP (not sniffing), close it
        if (arpOpenedDevice && !IsSniffing)
        {
            try { device?.StopCapture(); } catch { }
            try { device.OnPacketArrival -= Device_OnPacketArrival; } catch { }
            try { device?.Close(); } catch { }
            arpOpenedDevice = false;
        }
    }

    private void OpenFiltersEvent(object sender, ExecutedRoutedEventArgs e)
    {
        ShowPacketFilters();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // PHASE 3 — Content router (Network Monitor ↔ Filter pages)
    // PHASE 4 — Extended to ARP + 4 Tools sub-pages
    // ═══════════════════════════════════════════════════════════════════════════

    private enum ContentView
    {
        NetworkMonitor, PacketFilters, IspFilters, DeviceFilters,
        Arp, GeoIpLookup, NmapScanner, Ping, PacketTester,
        // Phase 5
        IpStorage, Hotspot,
        // Phase 6 — content-area Settings (sub-sidebar inside: Network/General/Hotkeys/Appearance/Performance)
        Settings,
        // Phase 8 — Traffic Control
        TrafficControl
    }
    private ContentView _currentContentView = ContentView.NetworkMonitor;

    private void ShowNetworkMonitor() => SwitchContent(ContentView.NetworkMonitor);
    private void ShowPacketFilters() => SwitchContent(ContentView.PacketFilters);
    private void ShowIspFilters() => SwitchContent(ContentView.IspFilters);
    private void ShowDeviceFilters() => SwitchContent(ContentView.DeviceFilters);
    private void ShowArp() => SwitchContent(ContentView.Arp);
    private void ShowGeoIpLookup() => SwitchContent(ContentView.GeoIpLookup);
    private void ShowNmapScanner() => SwitchContent(ContentView.NmapScanner);
    private void ShowPing() => SwitchContent(ContentView.Ping);
    private void ShowPacketTester() => SwitchContent(ContentView.PacketTester);
    private void ShowIpStorage() => SwitchContent(ContentView.IpStorage);
    private void ShowHotspot() => SwitchContent(ContentView.Hotspot);
    private void ShowSettings() => SwitchContent(ContentView.Settings);
    private void ShowTrafficControl() => SwitchContent(ContentView.TrafficControl);

    private void SwitchContent(ContentView target)
    {
        _currentContentView = target;

        NetworkMonitorView.Visibility = target == ContentView.NetworkMonitor
            ? Visibility.Visible : Visibility.Collapsed;

        if (target == ContentView.PacketFilters)
        {
            if (PacketFiltersHost.Content is not RhinoSniff.Views.PacketFilters)
                PacketFiltersHost.Content = new RhinoSniff.Views.PacketFilters(this);
            PacketFiltersHost.Visibility = Visibility.Visible;
        }
        else PacketFiltersHost.Visibility = Visibility.Collapsed;

        if (target == ContentView.IspFilters)
        {
            if (IspFiltersHost.Content is not RhinoSniff.Views.IspFilters)
                IspFiltersHost.Content = new RhinoSniff.Views.IspFilters(this);
            IspFiltersHost.Visibility = Visibility.Visible;
        }
        else IspFiltersHost.Visibility = Visibility.Collapsed;

        if (target == ContentView.DeviceFilters)
        {
            if (DeviceFiltersHost.Content is not RhinoSniff.Views.DeviceFilters)
                DeviceFiltersHost.Content = new RhinoSniff.Views.DeviceFilters(this);
            DeviceFiltersHost.Visibility = Visibility.Visible;
        }
        else DeviceFiltersHost.Visibility = Visibility.Collapsed;

        // ── Phase 4 hosts ───────────────────────────────────────────
        if (target == ContentView.Arp)
        {
            if (ArpHost.Content is not RhinoSniff.Views.ArpContent)
            {
                // Validate adapter + IPv4 before building the view
                if (NetworkAdapterComboBox.SelectedItem == null)
                {
                    ShowNotification(NotificationType.Info, "Please select a network adapter first.");
                    ArpHost.Visibility = Visibility.Collapsed;
                    ShowNetworkMonitor();
                    return;
                }
                var capDevice = GetCurrentCaptureDevice() as NpcapDevice;
                if (capDevice == null)
                {
                    ShowNotification(NotificationType.Alert, "Invalid capture device for ARP.");
                    ShowNetworkMonitor();
                    return;
                }
                if (capDevice.GetAddressFamily() == AddressFamily.IPv6)
                {
                    ShowNotification(NotificationType.Alert, "You must disable IPv6 to use ARP poisoning.");
                    ShowNetworkMonitor();
                    return;
                }
                if (capDevice.GetAddressFamily() == AddressFamily.Null)
                {
                    ShowNotification(NotificationType.Alert, "This adapter does not have a valid IP address.");
                    ShowNetworkMonitor();
                    return;
                }
                ArpHost.Content = new RhinoSniff.Views.ArpContent(this, capDevice);
            }
            ArpHost.Visibility = Visibility.Visible;
        }
        else ArpHost.Visibility = Visibility.Collapsed;

        if (target == ContentView.GeoIpLookup)
        {
            if (GeoIpHost.Content is not RhinoSniff.Views.GeoIpLookup)
                GeoIpHost.Content = new RhinoSniff.Views.GeoIpLookup();
            GeoIpHost.Visibility = Visibility.Visible;
        }
        else GeoIpHost.Visibility = Visibility.Collapsed;

        if (target == ContentView.NmapScanner)
        {
            if (NmapHost.Content is not RhinoSniff.Views.NmapScanner)
                NmapHost.Content = new RhinoSniff.Views.NmapScanner();
            NmapHost.Visibility = Visibility.Visible;
        }
        else NmapHost.Visibility = Visibility.Collapsed;

        if (target == ContentView.Ping)
        {
            if (PingHost.Content is not RhinoSniff.Views.PingTool)
                PingHost.Content = new RhinoSniff.Views.PingTool();
            PingHost.Visibility = Visibility.Visible;
        }
        else PingHost.Visibility = Visibility.Collapsed;

        if (target == ContentView.PacketTester)
        {
            if (PacketTesterHost.Content is not RhinoSniff.Views.PacketTester)
                PacketTesterHost.Content = new RhinoSniff.Views.PacketTester();
            PacketTesterHost.Visibility = Visibility.Visible;
        }
        else PacketTesterHost.Visibility = Visibility.Collapsed;

        // Phase 5
        if (target == ContentView.IpStorage)
        {
            if (IpStorageHost.Content is not RhinoSniff.Views.IPStorage)
                IpStorageHost.Content = new RhinoSniff.Views.IPStorage(this);
            IpStorageHost.Visibility = Visibility.Visible;
        }
        else IpStorageHost.Visibility = Visibility.Collapsed;

        if (target == ContentView.Hotspot)
        {
            if (HotspotHost.Content is not RhinoSniff.Views.Hotspot)
                HotspotHost.Content = new RhinoSniff.Views.Hotspot(this);
            HotspotHost.Visibility = Visibility.Visible;
        }
        else HotspotHost.Visibility = Visibility.Collapsed;

        if (target == ContentView.Settings)
        {
            if (SettingsHost.Content is not RhinoSniff.Views.SettingsHost)
                SettingsHost.Content = new RhinoSniff.Views.SettingsHost(this);
            SettingsHost.Visibility = Visibility.Visible;
        }
        else SettingsHost.Visibility = Visibility.Collapsed;

        // Phase 8: Traffic Control
        if (target == ContentView.TrafficControl)
        {
            if (TrafficControlHost.Content is not RhinoSniff.Views.TrafficControl)
                TrafficControlHost.Content = new RhinoSniff.Views.TrafficControl(this);
            TrafficControlHost.Visibility = Visibility.Visible;
        }
        else TrafficControlHost.Visibility = Visibility.Collapsed;

        UpdateSidebarActiveState(target);
    }

    private void UpdateSidebarActiveState(ContentView target)
    {
        // Use SetResourceReference (NOT direct FindResource + assign) so the
        // Foreground stays wired to DynamicResource and re-resolves on theme swap.
        // Assigning a Brush directly kills the XAML DynamicResource binding and
        // freezes the button at whatever color was current at first assignment.
        void SetFg(Control c, bool isActive)
        {
            if (c == null) return;
            c.SetResourceReference(Control.ForegroundProperty,
                isActive ? "SidebarItemActive" : "SidebarItemInactive");
        }

        SetFg(NavNetworkButton, target == ContentView.NetworkMonitor);
        SetFg(FilterButton, target is ContentView.PacketFilters
            or ContentView.IspFilters or ContentView.DeviceFilters);
        SetFg(NavPacketFiltersButton, target == ContentView.PacketFilters);
        SetFg(NavIspFiltersButton, target == ContentView.IspFilters);
        SetFg(NavDeviceFiltersButton, target == ContentView.DeviceFilters);

        // Phase 4 active states
        SetFg(ArpButton, target == ContentView.Arp);
        SetFg(ToolsButton, target is ContentView.GeoIpLookup
            or ContentView.NmapScanner or ContentView.Ping or ContentView.PacketTester);
        SetFg(NavGeoIpButton, target == ContentView.GeoIpLookup);
        SetFg(NavNmapButton, target == ContentView.NmapScanner);
        SetFg(NavPingButton, target == ContentView.Ping);
        SetFg(NavPacketTesterButton, target == ContentView.PacketTester);

        // Phase 5 active states
        SetFg(NavIpStorageButton, target == ContentView.IpStorage);
        SetFg(NavHotspotButton, target == ContentView.Hotspot);
        // Phase 6 active states
        SetFg(SettingsButton, target == ContentView.Settings);
        // Phase 8 active states
        SetFg(NavTrafficControlButton, target == ContentView.TrafficControl);
    }

    private void NavNetwork_Click(object sender, RoutedEventArgs e) => ShowNetworkMonitor();
    private void NavPacketFilters_Click(object sender, RoutedEventArgs e) => ShowPacketFilters();
    private void NavIspFilters_Click(object sender, RoutedEventArgs e) => ShowIspFilters();
    private void NavDeviceFilters_Click(object sender, RoutedEventArgs e) => ShowDeviceFilters();

    // Phase 5 nav handlers
    private void NavIpStorage_Click(object sender, RoutedEventArgs e) => ShowIpStorage();
    private void NavHotspot_Click(object sender, RoutedEventArgs e) => ShowHotspot();
    // Phase 6: standalone NavHotkeys sidebar button removed — Settings → Hotkeys sub-page now.

    // Phase 4 nav handlers
    private void NavArp_Click(object sender, RoutedEventArgs e) => ShowArp();
    private void NavTrafficControl_Click(object sender, RoutedEventArgs e) => ShowTrafficControl();
    private void NavGeoIp_Click(object sender, RoutedEventArgs e) => ShowGeoIpLookup();
    private void NavNmap_Click(object sender, RoutedEventArgs e) => ShowNmapScanner();
    private void NavPing_Click(object sender, RoutedEventArgs e) => ShowPing();
    private void NavPacketTester_Click(object sender, RoutedEventArgs e) => ShowPacketTester();

    private void GenericToolWindow_Closed(object sender, EventArgs e)
    {
        var unDimScreen = FindResource("HideDim") as BeginStoryboard;
        unDimScreen?.Storyboard.Begin();
    }

    private async void OpenLogEvent(object sender, ExecutedRoutedEventArgs e)
    {
        try
        {
            await Task.Run(() =>
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        UseShellExecute = true,
                        FileName = Path.Combine(
                            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RhinoSniff",
                            "logfile.log")
                    },
                    EnableRaisingEvents = true
                };
                process.Start();
            });
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
        }
    }

    private void OpenSettingsEvent(object sender, ExecutedRoutedEventArgs e)
    {
        // Phase 6: Settings is now a content-area view with a sub-sidebar
        // (Network / General / Hotkeys / Appearance / Performance).
        ShowSettings();
    }

    /// <summary>
    /// Phase 7.1 Session 4: classify a packet's source platform for the
    /// FilterSource pill row (Packet / PSN / XBOX). Heuristics:
    /// (1) Port-based: 3074 → XBOX, 3478-3480 / 3658-3659 → PSN
    /// (2) ISP-based: ISP contains "Sony" → PSN, contains "Microsoft" → XBOX
    /// (3) Untagged otherwise (Platform.Unknown)
    /// Tagged once at AddToSource time, never recomputed.
    /// </summary>
    private static RhinoSniff.Models.Platform ClassifyPlatform(ushort port, string isp)
    {
        // Port heuristics first — strongest signal
        if (port == 3074) return RhinoSniff.Models.Platform.Xbox;
        if (port is 3478 or 3479 or 3480 or 3658 or 3659) return RhinoSniff.Models.Platform.Psn;

        // ISP fallback
        if (!string.IsNullOrEmpty(isp))
        {
            if (isp.Contains("Sony", System.StringComparison.OrdinalIgnoreCase) ||
                isp.Contains("PlayStation", System.StringComparison.OrdinalIgnoreCase) ||
                isp.Contains("SCEA", System.StringComparison.OrdinalIgnoreCase) ||
                isp.Contains("SCEE", System.StringComparison.OrdinalIgnoreCase))
                return RhinoSniff.Models.Platform.Psn;
            if (isp.Contains("Microsoft", System.StringComparison.OrdinalIgnoreCase) ||
                isp.Contains("Xbox", System.StringComparison.OrdinalIgnoreCase))
                return RhinoSniff.Models.Platform.Xbox;
        }
        return RhinoSniff.Models.Platform.Unknown;
    }

    /// <summary>
    /// Classify traffic type by port number for the "PACKET TYPE" column.
    /// </summary>
    private static string ClassifyPacketType(ushort port, string protocol)
    {
        return port switch
        {
            443 => "HTTPS Cloud",
            80 => "HTTP",
            53 => "DNS",
            8080 or 8443 => "HTTP Proxy",
            3478 or 3479 or 3480 => "STUN/TURN",
            >= 9000 and <= 9100 => "Fortnite",
            3074 => "Xbox/CoD P2P",
            6672 => "GTA/RDR2",
            >= 61455 and <= 61458 => "GTA/RDR2",
            >= 27000 and <= 27036 => "Steam/CS2",
            >= 7000 and <= 8000 => "Valorant/PUBG",
            >= 26000 and <= 26600 => "Overwatch",
            >= 28015 and <= 28016 => "Rust",
            >= 19132 and <= 19133 => "Minecraft",
            >= 19000 and <= 19999 => "Discord Voice",
            993 => "IMAP",
            _ => protocol?.ToUpperInvariant() == "UDP" ? "UDP Traffic" : "TCP Traffic"
        };
    }

    /// <summary>
    /// Checks if a UDP dest port matches ANY of the active game filters.
    /// Returns true if the packet should be KEPT, false if filtered out.
    /// </summary>
    private static bool PassesMultiFilter(ushort destPort, List<FilterPreset> filters)
    {
        foreach (var filter in filters)
        {
            switch (filter)
            {
                case FilterPreset.None: return true;
                case FilterPreset.UDP: return true;
                case FilterPreset.Fortnite when destPort >= 9000 && destPort <= 9100: return true;
                case FilterPreset.CallOfDuty when destPort == 3074 || (destPort >= 3478 && destPort <= 3480) || (destPort >= 4379 && destPort <= 4380) || (destPort >= 27000 && destPort <= 27031) || destPort == 28960: return true;
                case FilterPreset.Valorant when (destPort >= 5000 && destPort <= 5500) || (destPort >= 7000 && destPort <= 8000) || (destPort >= 8180 && destPort <= 8181): return true;
                case FilterPreset.PUBG when destPort >= 7080 && destPort <= 8000: return true;
                case FilterPreset.CSGO when destPort >= 27000 && destPort <= 27036: return true;
                case FilterPreset.RainbowSixSiege when destPort == 3074 || destPort == 3658 || destPort == 6015 || destPort == 6115 || destPort == 6150 || (destPort >= 10000 && destPort <= 10099): return true;
                case FilterPreset.Overwatch when (destPort >= 26000 && destPort <= 26600) || destPort == 6250: return true;
                case FilterPreset.Battlefield when destPort == 3659 || (destPort >= 14000 && destPort <= 14016) || destPort == 18000 || (destPort >= 21000 && destPort <= 21999) || (destPort >= 22990 && destPort <= 24000) || (destPort >= 25200 && destPort <= 25300): return true;
                case FilterPreset.Halo when destPort == 3074 || destPort == 3075: return true;
                case FilterPreset.Destiny when destPort == 3074 || destPort == 3097 || destPort == 3480: return true;
                case FilterPreset.GTAOnline when destPort == 6672 || (destPort >= 61455 && destPort <= 61458): return true;
                case FilterPreset.RDR2Online when destPort == 6672 || (destPort >= 61455 && destPort <= 61458): return true;
                case FilterPreset.Rust when (destPort >= 28015 && destPort <= 28016) || destPort == 28083: return true;
                case FilterPreset.ARK when (destPort >= 7777 && destPort <= 7778) || (destPort >= 27015 && destPort <= 27016): return true;
                case FilterPreset.DayZ when (destPort >= 2302 && destPort <= 2305) || destPort == 27016: return true;
                case FilterPreset.Minecraft when destPort >= 19132 && destPort <= 19133: return true;
                case FilterPreset.FIFA when destPort == 3659 || (destPort >= 9000 && destPort <= 9999) || (destPort >= 14000 && destPort <= 14016): return true;
                case FilterPreset.NBA2K when destPort == 3074 || (destPort >= 5000 && destPort <= 5500) || (destPort >= 3478 && destPort <= 3480): return true;
                case FilterPreset.DeadByDaylight when (destPort >= 27000 && destPort <= 27200) || (destPort >= 8010 && destPort <= 8400): return true;
                case FilterPreset.SeaOfThieves when destPort == 3074 || (destPort >= 3478 && destPort <= 3480): return true;
                case FilterPreset.Tekken when destPort == 3074: return true;
                case FilterPreset.MortalKombat when destPort == 3074: return true;
                case FilterPreset.Discord when (destPort >= 3478 && destPort <= 3480) || (destPort >= 19000 && destPort <= 19999): return true;
                case FilterPreset.GTAVConsole when destPort == 3074 || destPort == 6672 || (destPort >= 61455 && destPort <= 61458): return true;
                // Payload-based filters can't be checked by port alone — handled separately
                case FilterPreset.PSNParty:
                case FilterPreset.XboxPartyBETA:
                case FilterPreset.RocketLeague:
                case FilterPreset.ApexLegends:
                case FilterPreset.RecRoom:
                    break; // Skip — checked in PassesMultiFilterPayload
                case FilterPreset.Custom:
                {
                    // Snapshot to prevent concurrent modification if user adds filter while sniffing
                    var customs = Globals.Settings.CustomFilters;
                    if (customs == null) break;
                    foreach (var cf in customs.ToArray())
                    {
                        if (destPort >= cf.MinPort && destPort <= cf.MaxPort) return true;
                    }
                    break;
                }
            }
        }
        return false; // Matched none
    }

    /// <summary>
    /// Phase 3 — does this specific UDP packet match the given filter preset?
    /// Mirrors the per-filter logic used inside the main eval switch, but usable
    /// to detect matches for Discard-action processing.
    /// </summary>
    private static bool PacketMatchesFilter(FilterPreset preset, ushort destPort, UdpPacket udpPacket)
    {
        switch (preset)
        {
            case FilterPreset.UDP: return true;
            case FilterPreset.Fortnite: return destPort >= 9000 && destPort <= 9100;
            case FilterPreset.CallOfDuty: return destPort == 3074 || (destPort >= 3478 && destPort <= 3480) || (destPort >= 4379 && destPort <= 4380) || (destPort >= 27000 && destPort <= 27031) || destPort == 28960;
            case FilterPreset.Valorant: return (destPort >= 5000 && destPort <= 5500) || (destPort >= 7000 && destPort <= 8000) || (destPort >= 8180 && destPort <= 8181);
            case FilterPreset.RainbowSixSiege: return destPort == 3074 || destPort == 3658 || destPort == 6015 || destPort == 6115 || destPort == 6150 || (destPort >= 10000 && destPort <= 10099);
            case FilterPreset.PUBG: return destPort >= 7080 && destPort <= 8000;
            case FilterPreset.CSGO: return destPort >= 27000 && destPort <= 27036;
            case FilterPreset.Overwatch: return (destPort >= 26000 && destPort <= 26600) || destPort == 6250;
            case FilterPreset.Battlefield:
                return destPort == 3659 || (destPort >= 14000 && destPort <= 14016) ||
                       destPort == 18000 || (destPort >= 21000 && destPort <= 21999) ||
                       (destPort >= 22990 && destPort <= 24000) || (destPort >= 25200 && destPort <= 25300);
            case FilterPreset.Halo: return destPort == 3074 || destPort == 3075;
            case FilterPreset.Destiny: return destPort == 3074 || destPort == 3097 || destPort == 3480;
            case FilterPreset.GTAOnline: return destPort == 6672 || (destPort >= 61455 && destPort <= 61458);
            case FilterPreset.RDR2Online: return destPort == 6672 || (destPort >= 61455 && destPort <= 61458);
            case FilterPreset.Rust: return (destPort >= 28015 && destPort <= 28016) || destPort == 28083;
            case FilterPreset.GTAVConsole: return destPort == 3074 || destPort == 6672 || (destPort >= 61455 && destPort <= 61458);
            case FilterPreset.ARK: return (destPort >= 7777 && destPort <= 7778) || (destPort >= 27015 && destPort <= 27016);
            case FilterPreset.DayZ: return (destPort >= 2302 && destPort <= 2305) || destPort == 27016;
            case FilterPreset.Minecraft: return destPort >= 19132 && destPort <= 19133;
            case FilterPreset.FIFA:
                return destPort == 3659 || (destPort >= 9000 && destPort <= 9999) || (destPort >= 14000 && destPort <= 14016);
            case FilterPreset.NBA2K:
                return destPort == 3074 || (destPort >= 5000 && destPort <= 5500) || (destPort >= 3478 && destPort <= 3480);
            case FilterPreset.DeadByDaylight:
                return (destPort >= 27000 && destPort <= 27200) || (destPort >= 8010 && destPort <= 8400);
            case FilterPreset.SeaOfThieves: return destPort == 3074 || (destPort >= 3478 && destPort <= 3480);
            case FilterPreset.Tekken: return destPort == 3074;
            case FilterPreset.MortalKombat: return destPort == 3074;
            case FilterPreset.Discord:
                return (destPort >= 3478 && destPort <= 3480) || (destPort >= 19000 && destPort <= 19999);
            case FilterPreset.RecRoom: return destPort == 5056;
            case FilterPreset.PSNParty:
            {
                if (udpPacket == null) return false;
                var len = udpPacket.PayloadDataSegment.Length;
                var p = destPort.ToString();
                return len == 64 && p.Length == 5 && (p.StartsWith("5") || p.StartsWith("6"));
            }
            case FilterPreset.XboxPartyBETA:
                return udpPacket?.PayloadData != null && udpPacket.PayloadData.Length == 56;
            case FilterPreset.RocketLeague:
                return udpPacket?.PayloadData != null && udpPacket.PayloadData.Length == 80;
            case FilterPreset.ApexLegends:
            {
                var p = destPort.ToString();
                return p.Length == 5 && (p.StartsWith("37") || p.StartsWith("39"));
            }
            case FilterPreset.Custom:
            {
                var customs = Globals.Settings.CustomFilters;
                if (customs == null) return false;
                foreach (var cf in customs.ToArray())
                    if (destPort >= cf.MinPort && destPort <= cf.MaxPort) return true;
                return false;
            }
            default: return false;
        }
    }

    /// <summary>
    /// Phase 3 — returns true if any currently active filter has action=Discard
    /// AND the packet matches that filter. Caller should drop the packet.
    /// </summary>
    private static bool ShouldDiscardPacket(ProtocolType protocol, ushort destPort, UdpPacket udpPacket)
    {
        var active = Globals.Settings.ActiveGameFilters;
        if (active == null || active.Count == 0) return false;
        var actions = Globals.Settings.FilterActions;
        if (actions == null || actions.Count == 0) return false;

        foreach (var preset in active)
        {
            if (!actions.TryGetValue(preset, out var act) || act != FilterAction.Discard) continue;

            if (preset == FilterPreset.TCP && protocol == ProtocolType.Tcp) return true;
            if (protocol != ProtocolType.Udp) continue;
            if (PacketMatchesFilter(preset, destPort, udpPacket)) return true;
        }
        return false;
    }

    // ── Phase 9: User-created filter matching ─────────────────────────────
    // Runs in parallel to the built-in preset switch. Returns whether ANY active
    // user filter matched and, if so, which action to take. Called from PacketParser
    // immediately after the preset switch so user filters compose with, not replace,
    // community filters.

    /// <summary>
    /// Check if any active UserFilter matches this packet. Returns (matched, action).
    /// First match wins on action priority: Discard beats Highlight (a discarded
    /// packet can never be highlighted). Called per-packet, keep it tight.
    /// </summary>
    private static (bool matched, FilterAction action) UserFilterMatch(
        ProtocolType protocol,
        ushort srcPort,
        ushort destPort,
        int packetLen,
        byte[] payload,
        IPAddress srcAddr,
        IPAddress dstAddr)
    {
        var list = Globals.Settings.UserFilters;
        if (list == null || list.Count == 0) return (false, FilterAction.Highlight);

        var highlight = false;
        foreach (var f in list)
        {
            if (!f.IsActive) continue;

            // Protocol gate
            var isTcp = protocol == ProtocolType.Tcp;
            var isUdp = protocol == ProtocolType.Udp;
            switch (f.Protocol)
            {
                case FilterProtocol.Tcp when !isTcp: continue;
                case FilterProtocol.Udp when !isUdp: continue;
            }

            // Port range (0..65535 = match all, so a no-op for unset ranges)
            if (f.PortStart > 0 || f.PortEnd < 65535)
            {
                var dp = destPort;
                if (dp < f.PortStart || dp > f.PortEnd) continue;
            }

            // Packet length range
            if (f.LenMin > 0 || f.LenMax < 65535)
            {
                if (packetLen < f.LenMin || packetLen > f.LenMax) continue;
            }

            // IP / CIDR (Local filters only — Cloud uses platforms as metadata)
            if (f.Source == UserFilterSource.Local && f.IpCidrs != null && f.IpCidrs.Count > 0)
            {
                var ipHit = false;
                foreach (var cidr in f.IpCidrs)
                {
                    if (IpInCidr(srcAddr, cidr) || IpInCidr(dstAddr, cidr)) { ipHit = true; break; }
                }
                if (!ipHit) continue;
            }

            // Bytes pattern — payload must contain at least one pattern
            if (f.BytesPatternsHex != null && f.BytesPatternsHex.Count > 0)
            {
                if (payload == null || payload.Length == 0) continue;
                var patternHit = false;
                foreach (var hex in f.BytesPatternsHex)
                {
                    if (PayloadContainsHex(payload, hex)) { patternHit = true; break; }
                }
                if (!patternHit) continue;
            }

            // NOTE: Country + ISP matching requires the ip-api geo cache, which is
            // populated asynchronously after the packet is added to the grid. We can't
            // cheaply resolve both here in the hot path. For v3.x we skip country/ISP
            // match here — MatchedGameFilter highlighting still routes the packet to
            // Filtered Traffic via the primary preset path; country/ISP narrowing can
            // run as a post-add filter on the grid. TODO: wire a dedicated geo pass.

            // Match! Priority: Discard short-circuits immediately.
            if (f.Action == FilterAction.Discard)
                return (true, FilterAction.Discard);
            highlight = true;
        }

        return highlight ? (true, FilterAction.Highlight) : (false, FilterAction.Highlight);
    }

    /// <summary>
    /// Does the payload contain the given hex byte sequence? Case-insensitive input,
    /// expects hex chars only (caller should have filtered whitespace).
    /// </summary>
    private static bool PayloadContainsHex(byte[] payload, string hex)
    {
        if (string.IsNullOrEmpty(hex) || hex.Length % 2 != 0) return false;
        var needleLen = hex.Length / 2;
        if (needleLen == 0 || needleLen > payload.Length) return false;

        // Decode hex once
        var needle = new byte[needleLen];
        for (int i = 0; i < needleLen; i++)
        {
            if (!byte.TryParse(hex.AsSpan(i * 2, 2), System.Globalization.NumberStyles.HexNumber, null, out var b))
                return false;
            needle[i] = b;
        }

        // Naive scan — payloads are small (<=1500 bytes typical)
        for (int i = 0; i <= payload.Length - needleLen; i++)
        {
            var hit = true;
            for (int j = 0; j < needleLen; j++)
            {
                if (payload[i + j] != needle[j]) { hit = false; break; }
            }
            if (hit) return true;
        }
        return false;
    }

    /// <summary>
    /// IP-in-CIDR check. Accepts plain IP ("8.8.8.8") as exact match, or CIDR
    /// ("10.0.0.0/8") as range. IPv4 + IPv6 supported.
    /// </summary>
    private static bool IpInCidr(IPAddress addr, string cidr)
    {
        if (addr == null || string.IsNullOrWhiteSpace(cidr)) return false;
        try
        {
            var slashIdx = cidr.IndexOf('/');
            if (slashIdx < 0)
            {
                // Plain IP = exact match
                return IPAddress.TryParse(cidr.Trim(), out var target) && target.Equals(addr);
            }

            var ipPart = cidr.Substring(0, slashIdx).Trim();
            if (!int.TryParse(cidr.Substring(slashIdx + 1).Trim(), out var prefix)) return false;
            if (!IPAddress.TryParse(ipPart, out var networkAddr)) return false;
            if (networkAddr.AddressFamily != addr.AddressFamily) return false;

            var networkBytes = networkAddr.GetAddressBytes();
            var addrBytes = addr.GetAddressBytes();
            if (networkBytes.Length != addrBytes.Length) return false;
            if (prefix < 0 || prefix > networkBytes.Length * 8) return false;

            var fullBytes = prefix / 8;
            var remainBits = prefix % 8;

            for (int i = 0; i < fullBytes; i++)
                if (networkBytes[i] != addrBytes[i]) return false;

            if (remainBits > 0 && fullBytes < networkBytes.Length)
            {
                var mask = (byte)(0xFF << (8 - remainBits));
                if ((networkBytes[fullBytes] & mask) != (addrBytes[fullBytes] & mask)) return false;
            }
            return true;
        }
        catch { return false; }
    }

    // Debug packet logging — counts per drop reason
    private readonly ConcurrentDictionary<string, long> _dropCounters = new();
    private long _totalParsed;
    private long _totalAdded;
    private DateTime _lastDebugWrite = DateTime.MinValue;

    private void LogDrop(string reason)
    {
        _dropCounters.AddOrUpdate(reason, 1, (_, v) => v + 1);
    }

    private async void WriteDebugLog()
    {
        var now = DateTime.Now;
        if ((now - _lastDebugWrite).TotalSeconds < 5) return;
        _lastDebugWrite = now;
        try
        {
            var logPath = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "RhinoSniff", "packet_debug.log");
            var dir = System.IO.Path.GetDirectoryName(logPath);
            if (!System.IO.Directory.Exists(dir)) System.IO.Directory.CreateDirectory(dir);
            var lines = new System.Text.StringBuilder();
            lines.AppendLine($"=== {now:yyyy-MM-dd HH:mm:ss} ===");
            lines.AppendLine($"RAW NPCAP: total={Interlocked.Read(ref _rawArrivalCount)} tcpv4={Interlocked.Read(ref _rawTcpv4Arrival)} udpv4={Interlocked.Read(ref _rawUdpv4Arrival)} tcpv6={Interlocked.Read(ref _rawTcpv6Arrival)} udpv6={Interlocked.Read(ref _rawUdpv6Arrival)} otherv6={Interlocked.Read(ref _rawOtherv6Arrival)} other={Interlocked.Read(ref _rawOtherArrival)} parseFail={Interlocked.Read(ref _rawParseFailArrival)}");
            lines.AppendLine($"Total parsed: {Interlocked.Read(ref _totalParsed)}");
            lines.AppendLine($"Total added to grid: {Interlocked.Read(ref _totalAdded)}");
            lines.AppendLine($"Grid rows: dataSource={dataSource.Count} gamesDataSource={gamesDataSource.Count}");
            lines.AppendLine($"Settings: ShowTcp={Globals.Settings.ShowTcpPackets} ShowUdp={Globals.Settings.ShowUdpPackets} PortsInverse={Globals.Settings.PortsInverse} Ports=[{string.Join(",", Globals.Settings.Ports)}] DeviceIps=[{string.Join(",", Globals.Settings.DeviceFilterIps ?? new System.Collections.Generic.List<string>())}] IspRules=[{string.Join(",", Globals.Settings.IspFilters ?? new System.Collections.Generic.List<string>())}] IspBehavior={Globals.Settings.IspFilterBehavior} ActiveFilters=[{string.Join(",", Globals.Settings.ActiveGameFilters ?? new System.Collections.Generic.List<FilterPreset>())}]");
            lines.AppendLine("Drop reasons:");
            foreach (var kvp in _dropCounters.OrderByDescending(x => x.Value))
                lines.AppendLine($"  {kvp.Key}: {kvp.Value}");
            lines.AppendLine();
            await System.IO.File.WriteAllTextAsync(logPath, lines.ToString());
        }
        catch { }
    }

    private async void PacketParser(PacketWrapper pw)
    {
        var destPort = 0;
        try
        {
            Interlocked.Increment(ref _totalParsed);

            if (pw.Protocol == ProtocolType.Reserved254) { LogDrop("Reserved254"); WriteDebugLog(); return; }

            if (pw.Protocol != ProtocolType.Tcp && pw.Protocol != ProtocolType.Udp) { LogDrop($"NotTcpUdp:{pw.Protocol}"); WriteDebugLog(); return; }

            if (!await Globals.Container.GetInstance<IPacketFilter>().FilterPacketAsync(pw)) { LogDrop("FilterPacketAsync=false"); WriteDebugLog(); return; }

            var packet = pw.Packet;

            if (packet == null) { LogDrop("PacketNull"); WriteDebugLog(); return; }

            // Note: ARP packet forwarding is handled in Device_OnPacketArrival (bidirectional)
            // Just flag the packet as spoofed for the skull icon display
            var isSpoofed = false;
            if (isPoisoning)
            {
                var ethPkt = packet.Extract<EthernetPacket>();
                if (ethPkt != null)
                {
                    var srcMac = ethPkt.SourceHardwareAddress.ToString();
                    var srcMacIsGateway = arpDevices.SourcePhysicalAddress != null &&
                                          srcMac.Contains(arpDevices.SourcePhysicalAddress.ToString());
                    var srcMacIsTarget = arpDevices.Targets != null &&
                                         arpDevices.Targets.Any(t => t?.Mac != null &&
                                                                     srcMac.Contains(t.Mac.ToString()));
                    isSpoofed = srcMacIsTarget || srcMacIsGateway;
                }
            }

            var tcpPacket = packet.Extract<TcpPacket>();
            var udpPacket = packet.Extract<UdpPacket>();

            // Bail if protocol says TCP/UDP but extraction failed (malformed packet)
            if (pw.Protocol == ProtocolType.Tcp && tcpPacket == null) { LogDrop("TcpExtractNull"); WriteDebugLog(); return; }
            if (pw.Protocol == ProtocolType.Udp && udpPacket == null) { LogDrop("UdpExtractNull"); WriteDebugLog(); return; }

            var destinationAddress = IPAddress.Any;
            var flagUri = string.Empty;

            IPPacket ipPacket = null;

            var protocol = pw.Protocol;
            
            // Extract IP packet early so UDP filters can access TTL, etc.
            var ipPacketEarly = packet.Extract<IPPacket>();

            // === LIVE TRAFFIC TRACKING ===
            // Track bytes for BOTH directions so upload/download counters work.
            // Upload = packet going TO a public IP (dst is remote)
            // Download = packet coming FROM a public IP (src is remote)
            if (ipPacketEarly != null)
            {
                var pktLen = ipPacketEarly.TotalLength;

                // Stats tracking
                Interlocked.Increment(ref totalPacketsSeen);
                Interlocked.Add(ref totalBytesSeen, pktLen);
                if (protocol == ProtocolType.Tcp) Interlocked.Increment(ref tcpCount);
                else if (protocol == ProtocolType.Udp) Interlocked.Increment(ref udpCount);
                var dst = ipPacketEarly.DestinationAddress;
                var src = ipPacketEarly.SourceAddress;

                // DIAGNOSTIC: count packets per direction relative to the ARP target IP
                // (only when poisoning is active). This tells us if world→target packets
                // are reaching PacketParser at all. If _ppDownToTarget stays 0 while
                // _ppUpFromTarget keeps climbing, the gateway-side ARP poison isn't
                // working — world→target packets bypass our PC entirely.
                if (isPoisoning && arpDevices.Targets != null)
                {
                    foreach (var t in arpDevices.Targets)
                    {
                        if (t?.Ip == null) continue;
                        if (src != null && src.Equals(t.Ip)) Interlocked.Increment(ref _ppUpFromTarget);
                        if (dst != null && dst.Equals(t.Ip)) Interlocked.Increment(ref _ppDownToTarget);
                    }
                }

                // Upload: destination is a public IP we're sending to
                if (dst != null && ValidateIP(dst))
                {
                    var key = dst.ToString();
                    var counter = trafficCounters.GetOrAdd(key, _ => new TrafficCounter());
                    counter.AddUpload(pktLen);
                }

                // Download: source is a public IP sending to us
                if (src != null && ValidateIP(src))
                {
                    var key = src.ToString();
                    var counter = trafficCounters.GetOrAdd(key, _ => new TrafficCounter());
                    counter.AddDownload(pktLen);
                }
            }
            
            var activeFilters = Globals.Settings.ActiveGameFilters;
            var useMultiFilter = activeFilters != null && activeFilters.Count > 0;
            var matchedGameFilter = false;
            
            switch (protocol)
            {
                case ProtocolType.Tcp when useMultiFilter:
                    // Multi-filter: check if TCP filter is in the active list
                    matchedGameFilter = activeFilters.Contains(FilterPreset.TCP);
                    break;
                case ProtocolType.Tcp when Globals.Settings.Filter is FilterPreset.UDP or FilterPreset.PSNParty
                    or FilterPreset.ApexLegends or FilterPreset.Discord or FilterPreset.GTAVConsole
                    or FilterPreset.RocketLeague or FilterPreset.RecRoom or FilterPreset.uTorrent
                    or FilterPreset.XboxPartyBETA or FilterPreset.Fortnite or FilterPreset.CallOfDuty
                    or FilterPreset.Valorant or FilterPreset.PUBG or FilterPreset.CSGO
                    or FilterPreset.Overwatch or FilterPreset.Battlefield or FilterPreset.Halo
                    or FilterPreset.Destiny or FilterPreset.GTAOnline or FilterPreset.RDR2Online
                    or FilterPreset.Rust or FilterPreset.ARK or FilterPreset.DayZ
                    or FilterPreset.FIFA or FilterPreset.NBA2K or FilterPreset.DeadByDaylight
                    or FilterPreset.SeaOfThieves or FilterPreset.Tekken or FilterPreset.MortalKombat
                    or FilterPreset.RainbowSixSiege or FilterPreset.Minecraft or FilterPreset.Custom:
                    // UDP game filter active — TCP doesn't match, but still show in All Traffic
                    matchedGameFilter = false;
                    break;
                case ProtocolType.Tcp:
                {
                    // Single-filter: if Filter is TCP, this packet matches
                    if (Globals.Settings.Filter == FilterPreset.TCP)
                        matchedGameFilter = true;

                    break;
                }
                case ProtocolType.Udp:
                {
                    // Multi-filter mode: check all active filters
                    if (useMultiFilter)
                    {
                        // First: port-based check (fast)
                        var portPassed = PassesMultiFilter(udpPacket.DestinationPort, activeFilters);

                        if (!portPassed)
                        {
                            // Second: payload-based filters that can't be port-checked
                            var passedPayload = false;
                            foreach (var af in activeFilters)
                            {
                                switch (af)
                                {
                                    case FilterPreset.PSNParty:
                                        var psnLen = udpPacket.PayloadDataSegment.Length;
                                        var psnPort = udpPacket.DestinationPort;
                                        var psnPortLen = psnPort.ToString().Length;
                                        if (psnLen == 64 && psnPortLen == 5)
                                        {
                                            char[] psnAllowed = { '5', '6' };
                                            if (psnAllowed.Any(x => psnPort.ToString().StartsWith(x)))
                                                passedPayload = true;
                                        }
                                        break;
                                    case FilterPreset.XboxPartyBETA:
                                        if (udpPacket.PayloadData != null && udpPacket.PayloadData.Length == 56)
                                            passedPayload = true;
                                        break;
                                    case FilterPreset.RocketLeague:
                                        if (udpPacket.PayloadData != null && udpPacket.PayloadData.Length == 80)
                                            passedPayload = true;
                                        break;
                                    case FilterPreset.ApexLegends:
                                        var apexPort = udpPacket.DestinationPort;
                                        var apexPortLen = apexPort.ToString().Length;
                                        if (apexPortLen == 5)
                                        {
                                            string[] apexPrefixes = { "37", "39" };
                                            if (apexPrefixes.Any(p => apexPort.ToString().StartsWith(p)))
                                                passedPayload = true;
                                        }
                                        break;
                                }
                                if (passedPayload) break;
                            }

                            // Didn't match any filter — still show in All Traffic, just not Filtered Traffic
                            matchedGameFilter = passedPayload;
                        }
                        else
                        {
                            matchedGameFilter = true;
                        }

                        break;
                    }
                    
                    switch (Globals.Settings.Filter)
                    {
                        case FilterPreset.XboxPartyBETA when udpPacket.PayloadData != null && udpPacket.PayloadData.Length != 56:
                        case FilterPreset.TCP:
                        case FilterPreset.uTorrent when udpPacket.ValidUdpChecksum && ipPacketEarly != null && ipPacketEarly.TimeToLive != 128:
                        case FilterPreset.GenericTorrentClient
                            when udpPacket.DestinationPort != 6881 && udpPacket.ValidUdpChecksum:
                            matchedGameFilter = false;
                            break;
                        case FilterPreset.PSNParty:
                        {
                            var udpPacketLen = udpPacket.PayloadDataSegment.Length;
                            var destPortTmp = udpPacket.DestinationPort;
                            var portLen = udpPacket.DestinationPort.ToString().Length;
                            char[] allowedVals = {'5', '6'};
                            if (udpPacketLen == 64 && portLen == 5)
                            {
                                var valid = allowedVals.Any(x => destPortTmp.ToString().StartsWith(x));
                                matchedGameFilter = valid;
                            }
                            else
                            {
                                matchedGameFilter = false;
                            }

                            break;
                        }
                        case FilterPreset.RocketLeague when udpPacket.PayloadData != null && udpPacket.PayloadData.Length != 80:
                            matchedGameFilter = false;
                            break;
                        case FilterPreset.ApexLegends:
                        {
                            var destPortTmp = udpPacket.DestinationPort;
                            var portLen = udpPacket.DestinationPort.ToString().Length;
                            if (portLen == 5)
                            {
                                string[] allowedPortPrefixes = {"37", "39"};
                                var valid = allowedPortPrefixes.Any(item => destPortTmp.ToString().StartsWith(item));
                                matchedGameFilter = valid;
                            }
                            else
                            {
                                matchedGameFilter = false;
                            }

                            break;
                        }
                        case FilterPreset.RecRoom when udpPacket.DestinationPort != 5056:
                        case FilterPreset.Discord
                            when !(udpPacket.DestinationPort >= 3478 && udpPacket.DestinationPort <= 3480) &&
                                 !(udpPacket.DestinationPort >= 19000 && udpPacket.DestinationPort <= 19999):
                        case FilterPreset.RainbowSixSiege when udpPacket.DestinationPort != 3074 &&
                                                               udpPacket.DestinationPort != 3658 &&
                                                               udpPacket.DestinationPort != 6015 &&
                                                               udpPacket.DestinationPort != 6115 &&
                                                               udpPacket.DestinationPort != 6150 &&
                                                               !(udpPacket.DestinationPort >= 10000 && udpPacket.DestinationPort <= 10099):
                        case FilterPreset.Fortnite when udpPacket.DestinationPort < 9000 || udpPacket.DestinationPort > 9100:
                        case FilterPreset.CallOfDuty when udpPacket.DestinationPort != 3074 &&
                                                          !(udpPacket.DestinationPort >= 3478 && udpPacket.DestinationPort <= 3480) &&
                                                          !(udpPacket.DestinationPort >= 4379 && udpPacket.DestinationPort <= 4380) &&
                                                          !(udpPacket.DestinationPort >= 27000 && udpPacket.DestinationPort <= 27031) &&
                                                          udpPacket.DestinationPort != 28960:
                        case FilterPreset.Valorant when !(udpPacket.DestinationPort >= 5000 && udpPacket.DestinationPort <= 5500) &&
                                                        !(udpPacket.DestinationPort >= 7000 && udpPacket.DestinationPort <= 8000) &&
                                                        !(udpPacket.DestinationPort >= 8180 && udpPacket.DestinationPort <= 8181):
                        case FilterPreset.PUBG when udpPacket.DestinationPort < 7080 || udpPacket.DestinationPort > 8000:
                        case FilterPreset.CSGO when !(udpPacket.DestinationPort >= 27000 && udpPacket.DestinationPort <= 27036):
                        case FilterPreset.Overwatch when !(udpPacket.DestinationPort >= 26000 && udpPacket.DestinationPort <= 26600) &&
                                                          udpPacket.DestinationPort != 6250:
                        case FilterPreset.Battlefield when udpPacket.DestinationPort != 3659 &&
                                                           !(udpPacket.DestinationPort >= 14000 && udpPacket.DestinationPort <= 14016) &&
                                                           udpPacket.DestinationPort != 18000 &&
                                                           !(udpPacket.DestinationPort >= 21000 && udpPacket.DestinationPort <= 21999) &&
                                                           !(udpPacket.DestinationPort >= 22990 && udpPacket.DestinationPort <= 24000) &&
                                                           !(udpPacket.DestinationPort >= 25200 && udpPacket.DestinationPort <= 25300):
                        case FilterPreset.Halo when udpPacket.DestinationPort != 3074 &&
                                                    udpPacket.DestinationPort != 3075:
                        case FilterPreset.Destiny when udpPacket.DestinationPort != 3074 && udpPacket.DestinationPort != 3097 &&
                                                       udpPacket.DestinationPort != 3480:
                        case FilterPreset.GTAOnline when udpPacket.DestinationPort != 6672 &&
                                                         !(udpPacket.DestinationPort >= 61455 && udpPacket.DestinationPort <= 61458):
                        case FilterPreset.RDR2Online when udpPacket.DestinationPort != 6672 &&
                                                          !(udpPacket.DestinationPort >= 61455 && udpPacket.DestinationPort <= 61458):
                        case FilterPreset.GTAVConsole when udpPacket.DestinationPort != 3074 &&
                                                           udpPacket.DestinationPort != 6672 &&
                                                           !(udpPacket.DestinationPort >= 61455 && udpPacket.DestinationPort <= 61458):
                        case FilterPreset.Rust when !(udpPacket.DestinationPort >= 28015 && udpPacket.DestinationPort <= 28016) &&
                                                     udpPacket.DestinationPort != 28083:
                        case FilterPreset.ARK when !(udpPacket.DestinationPort >= 7777 && udpPacket.DestinationPort <= 7778) &&
                                                    !(udpPacket.DestinationPort >= 27015 && udpPacket.DestinationPort <= 27016):
                        case FilterPreset.DayZ when !(udpPacket.DestinationPort >= 2302 && udpPacket.DestinationPort <= 2305) &&
                                                     udpPacket.DestinationPort != 27016:
                        case FilterPreset.Minecraft when udpPacket.DestinationPort < 19132 || udpPacket.DestinationPort > 19133:
                        case FilterPreset.FIFA when udpPacket.DestinationPort != 3659 &&
                                                     !(udpPacket.DestinationPort >= 9000 && udpPacket.DestinationPort <= 9999) &&
                                                     !(udpPacket.DestinationPort >= 14000 && udpPacket.DestinationPort <= 14016):
                        case FilterPreset.NBA2K when udpPacket.DestinationPort != 3074 &&
                                                      !(udpPacket.DestinationPort >= 3478 && udpPacket.DestinationPort <= 3480) &&
                                                      !(udpPacket.DestinationPort >= 5000 && udpPacket.DestinationPort <= 5500):
                        case FilterPreset.DeadByDaylight when !(udpPacket.DestinationPort >= 27000 && udpPacket.DestinationPort <= 27200) &&
                                                               !(udpPacket.DestinationPort >= 8010 && udpPacket.DestinationPort <= 8400):
                        case FilterPreset.SeaOfThieves when udpPacket.DestinationPort != 3074 &&
                                                            !(udpPacket.DestinationPort >= 3478 && udpPacket.DestinationPort <= 3480):
                        case FilterPreset.Tekken when udpPacket.DestinationPort != 3074:
                        case FilterPreset.MortalKombat when udpPacket.DestinationPort != 3074:
                            matchedGameFilter = false;
                            break;
                        case FilterPreset.Custom:
                        {
                            var customs = Globals.Settings.CustomFilters;
                            if (customs.Count > 0)
                            {
                                var matched = false;
                                var dp = udpPacket.DestinationPort;
                                foreach (var cf in customs.ToArray())
                                {
                                    if (dp >= cf.MinPort && dp <= cf.MaxPort)
                                    {
                                        matched = true;
                                        break;
                                    }
                                }
                                matchedGameFilter = matched;
                            }
                            break;
                        }
                        case FilterPreset.None:
                            // No filter — everything passes but nothing goes to Filtered Traffic
                            matchedGameFilter = false;
                            break;
                        default:
                            // Filter is active and packet passed the when-clause → it matched
                            matchedGameFilter = true;
                            break;
                    }

                    break;
                }
            }

            // ── Phase 3: Discard-action filters drop matching packets entirely ──
            // (Runs AFTER matchedGameFilter is computed but BEFORE packet is added to any source.)
            {
                ushort dpForDiscard = protocol == ProtocolType.Udp
                    ? (udpPacket?.DestinationPort ?? 0)
                    : (tcpPacket?.DestinationPort ?? 0);
                if (ShouldDiscardPacket(protocol, dpForDiscard, udpPacket))
                {
                    LogDrop($"FilterDiscard:{protocol}:{dpForDiscard}");
                    WriteDebugLog();
                    return;
                }

                // ── Phase 9: User filter matching (runs alongside built-in presets) ──
                // UserFilter match → Discard drops packet; Highlight routes to Filtered Traffic
                // even if built-in preset didn't match. Community + user filters compose.
                try
                {
                    ushort srcPortForUf = protocol == ProtocolType.Udp
                        ? (udpPacket?.SourcePort ?? 0)
                        : (tcpPacket?.SourcePort ?? 0);
                    byte[] payloadForUf = protocol == ProtocolType.Udp
                        ? udpPacket?.PayloadData
                        : tcpPacket?.PayloadData;
                    int pktLenForUf = payloadForUf?.Length ?? 0;
                    IPPacket ipPktForUf = protocol == ProtocolType.Udp
                        ? (udpPacket?.ParentPacket as IPPacket)
                        : (tcpPacket?.ParentPacket as IPPacket);
                    IPAddress srcForUf = ipPktForUf?.SourceAddress;
                    IPAddress dstForUf = ipPktForUf?.DestinationAddress;

                    var (ufMatched, ufAction) = UserFilterMatch(
                        protocol, srcPortForUf, dpForDiscard, pktLenForUf,
                        payloadForUf, srcForUf, dstForUf);

                    if (ufMatched)
                    {
                        if (ufAction == FilterAction.Discard)
                        {
                            LogDrop($"UserFilterDiscard:{protocol}:{dpForDiscard}");
                            WriteDebugLog();
                            return;
                        }
                        // Highlight — mark as matched so the packet routes to Filtered Traffic.
                        matchedGameFilter = true;
                    }
                }
                catch { /* UF match is best-effort — never break the capture pipeline */ }
            }

            var status = true;
            switch (protocol)
            {
                case ProtocolType.Tcp:
                    ipPacket = (IPPacket) tcpPacket.ParentPacket;
                    if (!ValidateIP(ipPacket.DestinationAddress))
                    {
                        LogDrop($"TcpValidateIP:{ipPacket.DestinationAddress}");
                        status = false;
                        WriteDebugLog();
                        return;
                    }

                    destPort = tcpPacket.DestinationPort;
                    destinationAddress = ipPacket.DestinationAddress;
                    if (blacklistedPorts.Contains(destPort)) { LogDrop($"TcpBlacklistedPort:{destPort}"); WriteDebugLog(); return; }
                    if (Globals.Settings.PacketAnalyser)
                        analyserData.TryAdd(ipPacket.DestinationAddress, packet);
                    break;

                case ProtocolType.Udp:
                    ipPacket = (IPPacket) udpPacket.ParentPacket;
                    if (!ValidateIP(ipPacket.DestinationAddress))
                    {
                        LogDrop($"UdpValidateIP:{ipPacket.DestinationAddress}");
                        status = false;
                        WriteDebugLog();
                        return;
                    }

                    destPort = udpPacket.DestinationPort;
                    destinationAddress = ipPacket.DestinationAddress;
                    if (blacklistedPorts.Contains(destPort)) { LogDrop($"UdpBlacklistedPort:{destPort}"); WriteDebugLog(); return; }
                    if (Globals.Settings.PacketAnalyser)
                        analyserData.TryAdd(ipPacket.DestinationAddress, packet);
                    break;

                default:
                    LogDrop($"DefaultProtocol:{protocol}");
                    WriteDebugLog();
                    return;
            }

            // Port blacklist from Settings (user-configurable 80/443/53 etc)
            // Checks DESTINATION port only
            // PortsInverse = false: blacklist mode (block ports in list)
            // PortsInverse = true: whitelist mode (only show ports in list)
            if (Globals.Settings.Ports.Count > 0 && destPort > 0)
            {
                var portInList = Globals.Settings.Ports.Contains((ushort)destPort);
                if (Globals.Settings.PortsInverse)
                {
                    if (!portInList) { LogDrop($"PortWhitelist:{destPort}"); WriteDebugLog(); return; }
                }
                else
                {
                    if (portInList) { LogDrop($"PortBlacklist:{destPort}"); WriteDebugLog(); return; }
                }
            }

            // ── Phase 3: Device Filter allowlist (replaces legacy single ConsoleIpFilter) ──
            // If non-empty, only keep packets whose source OR destination IPv4 is in the list.
            var deviceIps = Globals.Settings.DeviceFilterIps;
            if (deviceIps != null && deviceIps.Count > 0 && ipPacket != null)
            {
                var srcStr = ipPacket.SourceAddress?.ToString() ?? "";
                var dstStr = ipPacket.DestinationAddress?.ToString() ?? "";
                var allowed = false;
                foreach (var ip in deviceIps)
                {
                    if (string.IsNullOrWhiteSpace(ip)) continue;
                    if (srcStr == ip || dstStr == ip) { allowed = true; break; }
                }
                if (!allowed) { LogDrop($"DeviceFilter:src={srcStr},dst={dstStr}"); WriteDebugLog(); return; }
            }

            if (status)
            {
                Interlocked.Increment(ref _totalAdded);
                var found = false;
                var label = string.Empty;
                foreach (var item in Globals.Settings.Labels.Where(item =>
                             item.IpAddress == destinationAddress.ToString()))
                {
                    found = true;
                    label = item.Name;
                }

                if (found)
                    await Dispatcher.InvokeAsync(() =>
                    {
                        AddToSource(new CaptureGrid
                        {
                            Label = label, Flag = flagUri, IpAddress = destinationAddress, Port = (ushort) destPort,
                            Country = string.Empty, State = string.Empty, City = string.Empty,
                            Isp = string.Empty, DDoSProtected = PackIconKind.Loading,
                            Protocol = protocol.ToString().ToUpper(),
                            Spoofed = isSpoofed ? PackIconKind.SkullCrossbonesOutline : PackIconKind.None
                        }, matchedGameFilter);
                    });
                else
                    await Dispatcher.InvokeAsync(() =>
                    {
                        AddToSource(new CaptureGrid
                        {
                            Flag = flagUri, IpAddress = destinationAddress, Port = (ushort) destPort,
                            Country = string.Empty,
                            State = string.Empty, City = string.Empty, Isp = string.Empty,
                            DDoSProtected = PackIconKind.Loading, Protocol = protocol.ToString().ToUpper(),
                            Spoofed = isSpoofed ? PackIconKind.SkullCrossbonesOutline : PackIconKind.None
                        }, matchedGameFilter);
                    });
            }
            WriteDebugLog();
        }
        catch (Exception error)
        {
            LogDrop($"EXCEPTION:{error.GetType().Name}:{error.Message}");
            WriteDebugLog();
            await error.AutoDumpExceptionAsync();
        }
    }

    private async void RefreshAdaptersEvent(object sender, ExecutedRoutedEventArgs e)
    {
        try
        {
            if (e.OriginalSource is System.Windows.Controls.Button btn)
                btn.IsEnabled = false;
            await Adapter.InitAdapters();
            InitAdapters();
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
            ShowNotification(NotificationType.Error, "Failed to refresh adapters.");
        }
        finally
        {
            if (e.OriginalSource is System.Windows.Controls.Button btn2)
                btn2.IsEnabled = true;
        }
    }

    private void RemoveAtMenuItemEvent(object sender, ExecutedRoutedEventArgs e)
    {
        if (MainDataGrid.SelectedItem == null || MainDataGrid.SelectedItem is not CaptureGrid dgObj) return;

        // Remove from the active tab's source
        if (activeTab == 1)
        {
            var idx = -1;
            for (int i = 0; i < gamesDataSource.Count; i++)
            {
                if (gamesDataSource[i].IpAddress?.Equals(dgObj.IpAddress) == true)
                { idx = i; break; }
            }
            if (idx >= 0) gamesDataSource.RemoveAt(idx);
        }
        else
        {
            var idx = -1;
            for (int i = 0; i < dataSource.Count; i++)
            {
                if (dataSource[i].IpAddress?.Equals(dgObj.IpAddress) == true)
                { idx = i; break; }
            }
            if (idx >= 0) dataSource.RemoveAt(idx);
        }

        analyserData.TryRemove(dgObj.IpAddress, out _);
        UpdateTabBadges();
        UpdateStatusBar();
        ShowNotification(NotificationType.Info, "Removed the selected item.");
    }

    // Phase 6: ResetBackgroundEvent removed — content-area Settings → Appearance
    // handles the clear/reset flow directly in Views/SettingsAppearance.xaml.cs.

    private async void ResetTitle()
    {
        try
        {
            await Dispatcher.InvokeAsync(() =>
            {
                WindowTitleText.Text =
                    $"RhinoSniff v{Assembly.GetExecutingAssembly().GetRhinoSniffVersion()} - Idle";
            });
        }
        catch (Exception)
        {
        }
    }

    // Phase 6: SetBackgroundEvent + SettingsLoadHandlerEvent removed —
    // content-area Settings sub-pages own their save flows directly.


    private async void SetTitle(string title)
    {
        await Dispatcher.InvokeAsync(() =>
        {
            WindowTitleText.Text =
                $"RhinoSniff v{Assembly.GetExecutingAssembly().GetRhinoSniffVersion()} - {title}";
        });
    }

    private async void ShowNotification(NotificationType type, string message)
    {
        await Dispatcher.InvokeAsync(async () =>
        {
            var openNotificationAnimation = FindResource("OpenNotif") as BeginStoryboard;
            var closeNotificationAnimation = FindResource("CloseNotif") as BeginStoryboard;
            if (isNotificationOpen)
            {
                closeNotificationAnimation?.Storyboard.Begin();
                isNotificationQueued = true;
            }

            isNotificationOpen = true;
            NotificationGrid.Visibility = Visibility.Visible;
            switch (type)
            {
                case NotificationType.Info:
                    NotificationIcon.Kind = PackIconKind.InfoCircleOutline;
                    NotificationTitle.Content = "Notice";
                    NotificationDescription.Text = message;
                    break;

                case NotificationType.Alert:
                    NotificationIcon.Kind = PackIconKind.WarningOutline;
                    NotificationTitle.Content = "Alert";
                    NotificationDescription.Text = message;
                    break;

                case NotificationType.Error:
                    NotificationIcon.Kind = PackIconKind.ErrorOutline;
                    NotificationTitle.Content = "Error";
                    NotificationDescription.Text = message;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }

            openNotificationAnimation?.Storyboard.Begin();
            if (!isNotificationQueued)
            {
                await Task.Delay(3000);
                isNotificationOpen = false;
                closeNotificationAnimation?.Storyboard.Begin();
            }

            isNotificationQueued = false;
        });
    }

    private async void Shutdown()
    {
        try
        {
            if (device != null)
            {
                await Dispatcher.InvokeAsync(() =>
                {
                    IsSniffing = false;
                    try { if (StatsLiveDot != null) StatsLiveDot.Visibility = System.Windows.Visibility.Collapsed; } catch { }
                    trafficUpdateTimer.Stop();
                    SettingsButton.IsEnabled = true;
                    ArpButton.IsEnabled = true;
                    SniffText.Text = "SNIFF";
                    SniffIcon.Kind = PackIconKind.Play;
                    SniffButton.SetResourceReference(System.Windows.Controls.Control.BackgroundProperty, "AccentTealDark");
                    NetworkAdapterComboBox.IsEnabled = true;
                    ipAddresses = null;
                    UpdateCaptureHeaderState(false);
                });
                if (isPoisoning)
                {
                    arpThreadStop = true;
                    if (arpThread != null && arpThread.IsAlive)
                        arpThread.Join(2000);
                    isPoisoning = false;
                }
                
                // Reset ARP toolbar button
                await Dispatcher.InvokeAsync(() =>
                {
                    if (ArpToggleButton.Visibility == Visibility.Visible)
                    {
                        ArpToggleText.Text = "START ARP";
                        ArpToggleIcon.Kind = PackIconKind.Play;
                        ArpToggleButton.SetResourceReference(System.Windows.Controls.Control.BackgroundProperty, "ToolbarBtnIdleBg");
                    }
                });

                ResetTitle();
                if (Globals.Settings.DiscordStatus)
                {
                    try
                    {
                        var rpc = Globals.Container.GetInstance<IDiscordPresenceService>();
                        rpc.UpdateDetails("Ready to capture");
                        rpc.UpdateState(string.Empty);
                    }
                    catch (Exception)
                    {
                        // Discord RPC may not be initialized, ignore
                    }
                }
                device.StopCapture();
                device.Close();
                device.OnPacketArrival -= arrivalEventHandler;
                device.OnCaptureStopped -= captureStoppedEventHandler;
                device = null;
                backgroundThreadStop = true;
                backgroundThread.Join();
                await Dispatcher.InvokeAsync(() => { SniffButton.IsEnabled = true; });
            }
            else
            {
                ShowNotification(NotificationType.Error, "Adapter is null");
            }
        }
        catch (Exception e)
        {
            await e.AutoDumpExceptionAsync();
            Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
            {
                Icon = MsgBox.MsgBoxIcon.Error, Button = MsgBox.MsgBoxBtn.Ok,
                Message = $"{Properties.Resources.GENERIC_EXCEPTION}\n\nWhat happened: {e.Message}"
            });
            Application.Current.Shutdown();
        }
    }

    [Obfuscation(Feature = "virtualization", Exclude = false)]
    private async void StartCapture()
    {
        try
        {
            device = GetCurrentCaptureDevice();
            if (device == null)
            {
                ShowNotification(NotificationType.Error, "Could not find the selected network adapter.");
                SniffButton.IsEnabled = true;
                return;
            }
            IsSniffing = true;
            try { if (StatsLiveDot != null) StatsLiveDot.Visibility = System.Windows.Visibility.Visible; } catch { }
            packetCount = 0;
            Dispatcher.Invoke(() => { dataSource.Clear(); gamesDataSource.Clear(); partyDataSource.Clear(); });
            // Sidebar nav stays enabled during sniffing
            packetStrings = new Queue<PacketWrapper>();
            lastStatisticsOutput = DateTime.Now;
            backgroundThreadStop = false;
            arpThreadStop = false;
            backgroundThread = new Thread(BackgroundThread)
            {
                Name = "RhinoSniff-Capture-Thread",
                Priority = ThreadPriority.AboveNormal,
                IsBackground = true
            };
            backgroundThread.Start();
            blacklistedAddresses = new List<IPAddress>();
            analyserData = new ConcurrentDictionary<IPAddress, Packet>();

            // Clear PCAP buffer for fresh capture
            lock (pcapLock) { pcapBuffer.Clear(); }
            Interlocked.Exchange(ref bandwidthPacketCount, 0);
            bandwidthLastReset = DateTime.UtcNow;
            trafficCounters.Clear();
            trafficUpdateTimer.Start();
            arrivalEventHandler = Device_OnPacketArrival;
            device.OnPacketArrival += arrivalEventHandler;
            captureStoppedEventHandler = Device_OnCaptureStopped;
            device.OnCaptureStopped += captureStoppedEventHandler;
            // If ARP already opened the device, don't re-open
            if (!arpOpenedDevice)
                OpenDeviceTunnelAware(device);
            else
                arpOpenedDevice = false; // Capture now owns device lifecycle

            // Phase 6: apply configured kernel buffer size after device is open.
            // SharpPcap 5.4.0 exposes KernelBufferSize on LibPcapLiveDevice; NpcapDevice
            // inherits from it. Setter takes bytes; settings stores KB.
            try
            {
                if (device is SharpPcap.LibPcap.LibPcapLiveDevice live)
                {
                    var kb = Globals.Settings.CaptureBufferSizeKb;
                    if (kb < 64) kb = 64;
                    if (kb > 16384) kb = 16384;
                    live.KernelBufferSize = (uint)(kb * 1024);
                }
            }
            catch (Exception bufEx) { _ = bufEx.AutoDumpExceptionAsync(); }

            captureStatistics = device.Statistics;
            UpdateCaptureStatistics();
            if (isPoisoning)
            {
                var hasMulti = arpDevices.Targets != null && arpDevices.Targets.Count > 0;
                var hasLegacy = arpDevices.TargetLocalAddress != null && arpDevices.TargetPhysicalAddress != null;
                if (arpDevices.SourceLocalAddress == null || arpDevices.SourcePhysicalAddress == null ||
                    (!hasMulti && !hasLegacy))
                {
                    ShowNotification(NotificationType.Error,
                        "ARP: You need to select a source device and at least one target!");
                    return;
                }

                // Only start new ARP thread if one isn't already running
                if (arpThread == null || !arpThread.IsAlive)
                {
                    arpThreadStop = false;
                    arpThread = new Thread(ArpThread)
                    {
                        Name = "RhinoSniff-ARP-Thread",
                        IsBackground = true,
                        Priority = ThreadPriority.BelowNormal
                    };
                    arpThread.Start();
                }
            }

            device.StartCapture();
            NetworkAdapterComboBox.IsEnabled = false;

            if (Globals.Settings.DiscordStatus)
            {
                var rpc = Globals.Container.GetInstance<IDiscordPresenceService>();
                rpc.Initialize();
                rpc.UpdateDetails("Capturing");
                var connCount = dataSource.Count;
                rpc.UpdateState(connCount == 0 ? "" : connCount == 1 ? "1 connection found" : $"{connCount:N0} connections found");
            }
            SniffText.Text = "STOP";
            SniffIcon.Kind = PackIconKind.Stop;
            SniffButton.SetResourceReference(System.Windows.Controls.Control.BackgroundProperty, "StatusDanger");
            SniffButton.IsEnabled = true;
            UpdateCaptureHeaderState(true);
        }
        catch (Exception e)
        {
            await e.AutoDumpExceptionAsync();
            Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
            {
                Icon = MsgBox.MsgBoxIcon.Error, Button = MsgBox.MsgBoxBtn.Ok,
                Message = $"{Properties.Resources.CAPTURE_EXCEPTION}\n\nWhat happened: {e.Message}"
            });
            Environment.Exit(1);
        }
    }

    private void Dimmer_MouseDown(object sender, MouseButtonEventArgs e)
    {
        // Clicking the dimmer overlay closes the side panel
        if (settingsView)
        {
            var cmd = HideSideView;
            if (cmd.CanExecute(null, this))
                cmd.Execute(null, this);
        }
    }

    private void ToolsButton_Click(object sender, RoutedEventArgs e)
    {
        ToggleSubItems(ToolsSubItems, ToolsChevron);
    }

    private void FilterButton_Click(object sender, RoutedEventArgs e)
    {
        ToggleSubItems(FilterSubItems, FilterChevron);
    }

    private void NavStub_Click(object sender, RoutedEventArgs e)
    {
        // Placeholder nav entries for phases 3-8. Shows a notification so clicks
        // aren't silent while the feature is pending.
        var label = (sender as FrameworkElement)?.Tag?.ToString() ?? "Coming soon";
        ShowNotification(NotificationType.Info, $"{label} — not yet implemented.");
    }

    private void SidebarCollapseButton_Click(object sender, RoutedEventArgs e)
    {
        var newState = !Globals.Settings.SidebarCollapsed;
        Globals.Settings.SidebarCollapsed = newState;
        ApplySidebarCollapsed(newState);
        _ = Globals.Container.GetInstance<IServerSettings>().UpdateSettingsAsync();
    }

    private void ToggleSubItems(StackPanel panel, MaterialDesignThemes.Wpf.PackIcon chevron)
    {
        if (panel == null) return;
        // In collapsed sidebar mode, don't expand sub-items (no room).
        if (Globals.Settings.SidebarCollapsed) return;

        var expanded = panel.Visibility == Visibility.Visible;
        panel.Visibility = expanded ? Visibility.Collapsed : Visibility.Visible;
        if (chevron != null)
            chevron.Kind = expanded
                ? MaterialDesignThemes.Wpf.PackIconKind.ChevronDown
                : MaterialDesignThemes.Wpf.PackIconKind.ChevronUp;
    }

    /// <summary>
    /// Applies the collapsed/expanded state to the sidebar:
    /// - collapsed = 56px icon-only (labels hidden, sub-panels force-hidden, brand trimmed)
    /// - expanded  = 180px normal width
    /// </summary>
    private void ApplySidebarCollapsed(bool collapsed)
    {
        try
        {
            SidebarColumn.Width = new GridLength(collapsed ? 56 : 180);

            // Hide brand text + version pill when collapsed, keep icon button visible
            if (SidebarBrandPanel != null)
                SidebarBrandPanel.Visibility = collapsed ? Visibility.Collapsed : Visibility.Visible;

            // Swap collapse chevron direction
            if (SidebarCollapseIcon != null)
                SidebarCollapseIcon.Kind = collapsed
                    ? MaterialDesignThemes.Wpf.PackIconKind.ChevronRight
                    : MaterialDesignThemes.Wpf.PackIconKind.ChevronLeft;

            // Hide text labels on all nav items when collapsed
            var labelVis = collapsed ? Visibility.Collapsed : Visibility.Visible;
            if (NavNetworkLabel != null) NavNetworkLabel.Visibility = labelVis;
            if (NavFilterLabel != null) NavFilterLabel.Visibility = labelVis;
            if (NavArpLabel != null) NavArpLabel.Visibility = labelVis;
            if (NavTcLabel != null) NavTcLabel.Visibility = labelVis;
            if (NavHotspotLabel != null) NavHotspotLabel.Visibility = labelVis;
            if (NavToolsLabel != null) NavToolsLabel.Visibility = labelVis;
            if (NavIpStorageLabel != null) NavIpStorageLabel.Visibility = labelVis;
            if (NavFaqLabel != null) NavFaqLabel.Visibility = labelVis;
            if (NavSettingsLabel != null) NavSettingsLabel.Visibility = labelVis;
            if (SniffText != null) SniffText.Visibility = labelVis;
            if (ArpToggleText != null) ArpToggleText.Visibility = labelVis;

            // Chevrons hidden when collapsed (no room; can't expand anyway)
            if (FilterChevron != null) FilterChevron.Visibility = labelVis;
            if (ToolsChevron != null) ToolsChevron.Visibility = labelVis;

            // Force sub-panels closed when collapsing (they have no room either)
            if (collapsed)
            {
                if (FilterSubItems != null) FilterSubItems.Visibility = Visibility.Collapsed;
                if (ToolsSubItems != null) ToolsSubItems.Visibility = Visibility.Collapsed;
                if (FilterChevron != null) FilterChevron.Kind = MaterialDesignThemes.Wpf.PackIconKind.ChevronDown;
                if (ToolsChevron != null) ToolsChevron.Kind = MaterialDesignThemes.Wpf.PackIconKind.ChevronDown;
            }

            // Adapter combo and adapter indicator text trim when collapsed
            if (NetworkAdapterComboBox != null)
                NetworkAdapterComboBox.Visibility = labelVis;
            if (SidebarAdapterText != null)
                SidebarAdapterText.Visibility = labelVis;
        }
        catch
        {
            // A broken collapse must never crash the window.
        }
    }

    private void Storyboard_Completed(object sender, EventArgs e)
    {
        Dimmer.Visibility = Visibility.Hidden;

        if (!settingsView) return;

        var hideSettings = FindResource("CloseSettings") as BeginStoryboard;
        hideSettings?.Storyboard.Begin();
        TogglePanel();
        settingsView = false;
    }

    private void Storyboard_Completed_1(object sender, EventArgs e)
    {
        Canvas.Visibility = Visibility.Hidden;
        MaxBottom.IsEnabled = true;
    }

    private void Storyboard_Completed_2(object sender, EventArgs e)
    {
        closeStoryBoardCompleted = true;
        try
        {
            Globals.Container.GetInstance<IDiscordPresenceService>().DeInitialize();
        }
        catch (Exception)
        {
            return;
        }

        Application.Current.Shutdown();
    }

    private void Storyboard_Completed_3(object sender, EventArgs e)
    {
        MaxBottom.IsEnabled = true;
    }

    private void Storyboard_Completed_4(object sender, EventArgs e)
    {
        NotificationGrid.Visibility = Visibility.Hidden;
    }

    private void TcpProbeMenuItemEvent(object sender, ExecutedRoutedEventArgs e)
    {
        if (MainDataGrid.SelectedItem is not CaptureGrid dgObj) return;

        TogglePanel(true);
        ChangeSideView(new Probe(dgObj.IpAddress, dgObj.Port), "TCP Probe");
        MaxBottom.IsEnabled = false;
        Dimmer.Visibility = Visibility.Visible;
        var dimScreen = FindResource("Dim") as BeginStoryboard;
        dimScreen?.Storyboard.Begin();
        var showSettings = FindResource("OpenSettings") as BeginStoryboard;
        showSettings?.Storyboard.Begin();
        settingsView = true;
    }

    [Obfuscation(Feature = "virtualization", Exclude = false)]
    private async void ToggleCaptureEvent(object sender, ExecutedRoutedEventArgs e)
    {
        try
        {
            SniffButton.IsEnabled = false;
            if (IsSniffing)
            {
                await Task.Run(Shutdown).ConfigureAwait(true);
                return;
            }

            if (NetworkAdapterComboBox.SelectedItem != null)
            {
                dataSource.Clear();
                gamesDataSource.Clear();
                ipAddresses = new List<IPAddress>();

                // Reset stats
                Interlocked.Exchange(ref totalPacketsSeen, 0);
                Interlocked.Exchange(ref totalBytesSeen, 0);
                Interlocked.Exchange(ref tcpCount, 0);
                Interlocked.Exchange(ref udpCount, 0);
                UpdateStatsBar();
                UpdateTabBadges();

                TogglePanel();
                StartCapture();
            }
            else
            {
                ShowNotification(NotificationType.Info, "Please select a network adapter first.");
                SniffButton.IsEnabled = true;
            }
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
            SniffButton.IsEnabled = true;
        }
    }

    private async void TogglePanel(bool sideView = false)
    {
        if (sideView)
        {
            await Dispatcher.InvokeAsync(() =>
            {
                if (!isControlPanelOpen) return;
                isControlPanelOpen = false;
            });
            return;
        }

        await Dispatcher.InvokeAsync(() =>
        {
            if (isControlPanelOpen)
            {
                isControlPanelOpen = false;
            }
            else
            {
                isControlPanelOpen = true;
            }
        });
    }

    private async void TogglePanelEvent(object sender, ExecutedRoutedEventArgs e)
    {
        try
        {
            TogglePanel();
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
        }
    }

    private async void UpdateCaptureStatistics()
    {
        try
        {
            var sniffing = false;
            await Dispatcher.InvokeAsync(() => { sniffing = IsSniffing; });
            if (!sniffing)
            {
                if (!authTask.IsEnabled)
                {
                    await Globals.Container.GetInstance<IErrorLogging>()
                        .WriteToLogAsync("Authentication thread is dead!", LogLevel.FATAL);
                    await Globals.Container.GetInstance<IErrorLogging>()
                        .WriteToLogAsync("Restarting authentication thread...", LogLevel.WARNING);
                    authTask.Start();
                }

                SetTitle("Idle");
                if (!Globals.Settings.DiscordStatus) return;

                Globals.Container.GetInstance<IDiscordPresenceService>().UpdateDetails("Ready to capture");

                return;
            }

            if (Globals.Settings.DiscordStatus)
            {
                var connCount = dataSource.Count;
                var stateText = connCount == 1
                    ? "1 connection found"
                    : $"{connCount:N0} connections found";
                Globals.Container.GetInstance<IDiscordPresenceService>().UpdateState(stateText);
            }

            SetTitle(
                $"Capturing - Received {captureStatistics.ReceivedPackets} Dropped: {captureStatistics.DroppedPackets} | {GetPacketsPerSecond()} pps");

            // Update stats bar on timer tick
            await Dispatcher.InvokeAsync(UpdateStatsBar);
        }
        catch (Exception e)
        {
            await e.AutoDumpExceptionAsync();
        }
    }

    private int GetPacketsPerSecond()
    {
        var now = DateTime.UtcNow;
        var elapsed = (now - bandwidthLastReset).TotalSeconds;
        if (elapsed < 1.0) return 0;
        var pps = (int)(bandwidthPacketCount / elapsed);
        Interlocked.Exchange(ref bandwidthPacketCount, 0);
        bandwidthLastReset = now;
        return pps;
    }

    /// <summary>
    /// Timer tick: update Upload/Download/Packets columns on every grid row from live counters.
    /// Runs on UI thread via DispatcherTimer. This is what makes the numbers tick up in real time
    /// when upload stops moving for an IP, that connection went dead.
    /// </summary>
    private void TrafficUpdateTimer_Tick(object sender, EventArgs e)
    {
        try
        {
            UpdateTrafficForList(dataSource);
            UpdateTrafficForList(gamesDataSource);
            UpdateTrafficForList(partyDataSource);

            // Auto remove inactive IPs (60s no traffic)
            if (Globals.Settings.AutoRemoveInactive)
            {
                var now = DateTime.Now;
                var threshold = TimeSpan.FromSeconds(60);
                for (int i = dataSource.Count - 1; i >= 0; i--)
                {
                    if (now - dataSource[i].LastSeenTime > threshold)
                    {
                        var ip = dataSource[i].IpAddress;
                        dataSource.RemoveAt(i);
                        ipAddresses?.Remove(ip);
                        // Also remove from gamesDataSource
                        for (int j = gamesDataSource.Count - 1; j >= 0; j--)
                        {
                            if (gamesDataSource[j].IpAddress?.Equals(ip) == true)
                            { gamesDataSource.RemoveAt(j); break; }
                        }
                    }
                }
            }
        }
        catch (Exception)
        {
            // Swallow — grid may be in flux during capture start/stop
        }
    }

    private void UpdateTrafficForList(NotifyBindingList<CaptureGrid> list)
    {
        var now = DateTime.Now;

        // First pass: find max packet count in this list (for the inline bar chart scale)
        long maxPkts = 1;
        for (var i = 0; i < list.Count; i++)
        {
            var key = list[i].IpAddress?.ToString();
            if (string.IsNullOrEmpty(key)) continue;
            if (trafficCounters.TryGetValue(key, out var c) && c.TotalPackets > maxPkts)
                maxPkts = c.TotalPackets;
        }

        for (var i = 0; i < list.Count; i++)
        {
            var row = list[i];
            var key = row.IpAddress?.ToString();
            if (string.IsNullOrEmpty(key)) continue;

            if (trafficCounters.TryGetValue(key, out var counter))
            {
                var newUp = TrafficCounter.FormatBytes(counter.UploadBytes);
                var newDown = TrafficCounter.FormatBytes(counter.DownloadBytes);
                var newPkts = counter.TotalPackets.ToString("N0");

                if (row.Upload != newUp || row.Download != newDown || row.Packets != newPkts)
                {
                    row.Upload = newUp;
                    row.Download = newDown;
                    row.Packets = newPkts;
                    row.LastSeenTime = now;
                }

                // Inline packets bar — scale 0-40px against the max in this list.
                // min 2px so active rows always show a sliver.
                var ratio = maxPkts <= 0 ? 0 : (double)counter.TotalPackets / maxPkts;
                var target = Math.Max(2.0, Math.Round(ratio * 40.0, 1));
                if (Math.Abs(row.PacketsBarWidth - target) > 0.5)
                    row.PacketsBarWidth = target;
            }

            // Refresh time-ago text
            var elapsed = now - row.LastSeenTime;
            var newText = elapsed.TotalSeconds < 3 ? "now"
                : elapsed.TotalSeconds < 60 ? $"{(int)elapsed.TotalSeconds}s"
                : elapsed.TotalMinutes < 60 ? $"{(int)elapsed.TotalMinutes}m"
                : $"{(int)elapsed.TotalHours}h";
            if (row.LastSeenText != newText)
                row.LastSeenText = newText;

            // CaptureGrid fires INotifyPropertyChanged on each property set above.
            // WPF bindings update automatically. No need for list.NotifyItemChanged().
        }
    }

    /// <summary>
    /// Syncs the content-area STOPPED/CAPTURING pill + Start Sniff/Stop Sniff button
    /// with the current capture state. Call whenever IsSniffing changes.
    /// </summary>
    private void UpdateCaptureHeaderState(bool capturing)
    {
        try
        {
            if (CaptureStatusPill != null)
                CaptureStatusPill.SetResourceReference(Border.BackgroundProperty,
                    capturing ? "PillCapturingBg" : "PillStoppedBg");
            if (CaptureStatusDot != null)
                CaptureStatusDot.SetResourceReference(System.Windows.Shapes.Shape.FillProperty,
                    capturing ? "PillCapturingText" : "PillStoppedText");
            if (CaptureStatusText != null)
            {
                CaptureStatusText.Text = capturing ? "CAPTURING" : "STOPPED";
                CaptureStatusText.SetResourceReference(TextBlock.ForegroundProperty,
                    capturing ? "PillCapturingText" : "PillStoppedText");
            }
            if (HeaderSniffText != null)
                HeaderSniffText.Text = capturing ? "Stop Sniff" : "Start Sniff";
            if (HeaderSniffIcon != null)
                HeaderSniffIcon.Kind = capturing
                    ? MaterialDesignThemes.Wpf.PackIconKind.Stop
                    : MaterialDesignThemes.Wpf.PackIconKind.Play;
        }
        catch { }
    }

    private async void ExportPcapMenuItemEvent(object sender, ExecutedRoutedEventArgs e)
    {
        try
        {
            List<RawCapture> snapshot;
            lock (pcapLock)
            {
                snapshot = new List<RawCapture>(pcapBuffer);
            }

            if (snapshot.Count == 0)
            {
                ShowNotification(NotificationType.Info, "No packets captured yet.");
                return;
            }

            SaveFileDialog dialog = new()
            {
                Title = "Export capture as PCAP...",
                Filter = "PCAP file (*.pcap) | *.pcap",
                CheckPathExists = true,
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
            };
            if (dialog.ShowDialog() == true)
            {
                await Task.Run(() =>
                {
                    var writer = new CaptureFileWriterDevice(dialog.FileName);
                    try
                    {
                        writer.Open();
                        foreach (var raw in snapshot)
                        {
                            writer.Write(raw);
                        }
                    }
                    finally
                    {
                        writer.Close();
                    }
                });
                ShowNotification(NotificationType.Info, $"Exported {snapshot.Count} packets to PCAP");
            }
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
            ShowNotification(NotificationType.Error, "Failed to export PCAP file.");
        }
    }

    private async void WhoisAllMenuItemEvent(object sender, ExecutedRoutedEventArgs e)
    {
        try
        {
            if (dataSource.Count == 0)
            {
                ShowNotification(NotificationType.Info, "No connections to export.");
                return;
            }

            SaveFileDialog dialog = new()
            {
                Title = "Export WHOIS data...",
                Filter = "Text document (*.txt) | *.txt",
                CheckPathExists = true,
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
            };
            if (dialog.ShowDialog() == true)
            {
                var lines = new List<string>();
                lines.Add($"RhinoSniff WHOIS Export - {DateTime.UtcNow} UTC");
                lines.Add($"Total connections: {dataSource.Count}");
                lines.Add(new string('=', 80));
                lines.Add("");

                foreach (var item in dataSource)
                {
                    lines.Add($"IP: {item.IpAddress}");
                    lines.Add($"  Port: {item.Port} ({item.Protocol})");
                    lines.Add($"  Country: {item.Country}");
                    lines.Add($"  State: {item.State}");
                    lines.Add($"  City: {item.City}");
                    lines.Add($"  ISP: {item.Isp}");
                    lines.Add($"  Label: {item.Label}");
                    lines.Add($"  Last Seen: {item.LastSeenText}");
                    lines.Add($"  Packet Type: {item.PacketType}");
                    lines.Add($"  Upload: {item.Upload}");
                    lines.Add($"  Download: {item.Download}");
                    lines.Add($"  Packets: {item.Packets}");
                    lines.Add($"  DDoS Protected: {(item.DDoSProtected == PackIconKind.LockOutline ? "Yes" : "No")}");
                    lines.Add("");
                }

                await File.WriteAllLinesAsync(dialog.FileName, lines);
                ShowNotification(NotificationType.Info, $"Exported WHOIS data for {dataSource.Count} connections");
            }
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
            ShowNotification(NotificationType.Error, "Failed to export WHOIS data.");
        }
    }

    private static System.Windows.Media.Color SafeParseColor(string hex)
    {
        try
        {
            if (!string.IsNullOrEmpty(hex) && hex.StartsWith("#"))
                return (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(hex);
        }
        catch { }
        return (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#00897B");
    }

    private static SolidColorBrush SafeParseColorName(string name)
    {
        try
        {
            if (!string.IsNullOrEmpty(name))
                return new SolidColorBrush(
                    (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(name));
        }
        catch { }
        return new SolidColorBrush(System.Windows.Media.Color.FromRgb(0, 137, 123));
    }

    private bool ValidateIP(IPAddress ipAddr)
    {
        try
        {
            if (ipAddr == null) return false;

            if (ipAddr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                // Allow public IPv6, reject private/reserved
                if (IPAddress.IsLoopback(ipAddr)) return false;              // ::1
                if (ipAddr.IsIPv6LinkLocal) return false;                    // fe80::/10
                if (ipAddr.IsIPv6SiteLocal) return false;                    // fec0::/10
                if (ipAddr.IsIPv6Multicast) return false;                    // ff00::/8
                var bytes = ipAddr.GetAddressBytes();
                if (bytes[0] == 0xFC || bytes[0] == 0xFD) return false;      // fc00::/7 ULA
                if (bytes.All(b => b == 0)) return false;                    // ::

                if (blacklistedAddresses == null || blacklistedAddresses.Count == 0) return true;
                return !blacklistedAddresses.Contains(ipAddr);
            }

            // IPv4
            var b4 = ipAddr.GetAddressBytes();
            if (b4.Length != 4) return false;

            if (b4[0] == 10) return false;                                           // 10.0.0.0/8
            if (b4[0] == 172 && b4[1] >= 16 && b4[1] <= 31) return false;           // 172.16.0.0/12
            if (b4[0] == 192 && b4[1] == 168) return false;                         // 192.168.0.0/16
            if (b4[0] == 127) return false;                                          // 127.0.0.0/8 loopback
            if (b4[0] == 0) return false;                                            // 0.0.0.0/8
            if (b4[0] == 169 && b4[1] == 254) return false;                         // 169.254.0.0/16 link-local
            if (b4[0] == 255 && b4[1] == 255 && b4[2] == 255 && b4[3] == 255) return false; // broadcast
            if (b4[0] >= 224 && b4[0] <= 239) return false;                         // 224.0.0.0/4 multicast

            if (blacklistedAddresses == null || blacklistedAddresses.Count == 0) return true;
            return !blacklistedAddresses.Contains(ipAddr);
        }
        catch (Exception)
        {
            return false;
        }
    }

    private void Window_Activated(object sender, EventArgs e)
    {
        try
        {
            Border.BorderBrush = Globals.Settings.ColorType switch
            {
                ColorType.Custom => new SolidColorBrush(
                    SafeParseColor(Globals.Settings.HexColor)),
                ColorType.Accent => new SolidColorBrush(SystemParameters.WindowGlassColor),
                ColorType.Default => new SolidColorBrush(Color.FromRgb(0, 137, 123)),
                _ => SafeParseColorName(Globals.Settings.ColorType.ToString())
            };
        }
        catch (Exception ex)
        {
            _ = ex.AutoDumpExceptionAsync();
        }
    }

    private async void Window_Closing(object sender, CancelEventArgs e)
    {
        if (closeStoryBoardCompleted) return;

        // Safety: if ARP is still running on shutdown, stop it so ARP caches get restored
        // cleanly instead of leaving the target black-holed.
        if (isPoisoning)
        {
            try { StopArpPoisoning(); } catch { }
        }

        // B3: if TC engine is running, stop it cleanly so the WinDivert handle is disposed
        // and queued packets aren't dropped on the floor by runtime thread termination.
        try
        {
            if (TrafficControlHost?.Content is RhinoSniff.Views.TrafficControl tcView && tcView.IsRunning)
                tcView.ForceStop();
        }
        catch { }

        if (IsSniffing)
        {
            if (Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
                {
                    Icon = MsgBox.MsgBoxIcon.Question, Button = MsgBox.MsgBoxBtn.YesNo,
                    Message = Properties.Resources.CAPTURE_ACTIVE_EXIT
                }) == MsgBox.MsgBoxResult.No)
            {
                e.Cancel = true;
                CloseButton.IsEnabled = true;
                return;
            }

            await Task.Run(Shutdown).ConfigureAwait(true);
        }

        var sb = FindResource("CloseAnim") as BeginStoryboard;
        sb?.Storyboard.Begin();
        e.Cancel = true;
    }

    private void Window_Deactivated(object sender, EventArgs e)
    {
        Border.BorderBrush = new SolidColorBrush(Color.FromRgb(64, 64, 64));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 5 — public API for child views + hotkey routing
    // ═══════════════════════════════════════════════════════════════════════

    private RhinoSniff.Classes.GlobalHotkeyManager _hotkeys;

    /// <summary>
    /// Hotkey manager — child views (HotkeysSettings) read this to re-register bindings
    /// without blowing away others on conflict. Null during early startup only.
    /// </summary>
    public RhinoSniff.Classes.GlobalHotkeyManager Hotkeys => _hotkeys;

    /// <summary>
    /// Public wrapper so child UserControls can trigger MainWindow notifications without
    /// reflection. Always dispatched to UI thread.
    /// </summary>
    public void NotifyPublic(NotificationType type, string message)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.BeginInvoke(new Action(() => NotifyPublic(type, message))); return; }
        try { ShowNotification(type, message); } catch { /* don't let notification failure cascade */ }
    }

    /// <summary>
    /// Phase 6: public wrapper for <see cref="LoadBackground"/> called from the
    /// content-area Settings → Appearance sub-page after the BUG #1 GUID-copy.
    /// </summary>
    public bool PublicLoadBackground(string path)
    {
        if (!Dispatcher.CheckAccess()) return (bool)Dispatcher.Invoke(new Func<bool>(() => PublicLoadBackground(path)));
        try { return LoadBackground(path); } catch { return false; }
    }

    /// <summary>
    /// Phase 6: public wrapper for <see cref="ClearBackground"/>.
    /// </summary>
    public void PublicClearBackground()
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.Invoke(new Action(PublicClearBackground)); return; }
        try { ClearBackground(); } catch { }
    }

    /// <summary>
    /// Route a <see cref="HotkeyAction"/> to the matching app behavior. Called both by
    /// the hotkey manager (WM_HOTKEY) and by the Hotkeys Settings "Test" buttons.
    /// </summary>
    public void FireHotkeyAction(HotkeyAction action)
    {
        try
        {
            switch (action)
            {
                case HotkeyAction.ToggleCapture:
                    if (ToggleCapture.CanExecute(null, this))
                        ToggleCapture.Execute(null, this);
                    break;
                case HotkeyAction.ClearCapture:
                    if (ClearAllCommand.CanExecute(null, this))
                        ClearAllCommand.Execute(null, this);
                    break;
                case HotkeyAction.SwitchTrafficView:
                    try
                    {
                        if (AllTrafficTab != null && FilteredTrafficTab != null)
                        {
                            var nowAll = !(AllTrafficTab.IsChecked ?? false);
                            AllTrafficTab.IsChecked = nowAll;
                            FilteredTrafficTab.IsChecked = !nowAll;
                            if (nowAll) AllTrafficTab_Click(this, new RoutedEventArgs());
                            else FilteredTrafficTab_Click(this, new RoutedEventArgs());
                        }
                    } catch { }
                    break;
                case HotkeyAction.ToggleArp:
                    try { ArpToggleButton_Click(this, new RoutedEventArgs()); } catch { }
                    break;
                case HotkeyAction.GoToNetworkMonitor: ShowNetworkMonitor(); break;
                case HotkeyAction.GoToPacketFilters: ShowPacketFilters(); break;
                case HotkeyAction.GoToArp:
                    // ARP nav has adapter prereqs — reuse the sidebar click handler which enforces them
                    try { NavArp_Click(this, new RoutedEventArgs()); } catch { ShowArp(); }
                    break;
                case HotkeyAction.GoToSettings:
                    ShowSettings();
                    break;
                case HotkeyAction.QuickExportCsv:
                    // ExportCommand is wired per-row via CommandParameter — for a bulk
                    // hotkey export, fall back to the same path the Export button uses.
                    try { ExportMenuItemEvent(this, null); } catch { }
                    break;
            }
        }
        catch (Exception e)
        {
            _ = e.AutoDumpExceptionAsync();
        }
    }

    private void MainWindow_Loaded_Phase5(object sender, RoutedEventArgs e)
    {
        // Register persisted hotkeys. Conflicts surface as a single notification so startup
        // doesn't spam (e.g. user had Ctrl+Shift+C bound and another app now owns it).
        try
        {
            var failures = _hotkeys?.ApplyFromSettings();
            if (failures != null && failures.Count > 0)
            {
                var msg = $"{failures.Count} hotkey binding(s) couldn't be registered (conflict or invalid). Open Hotkeys to reassign.";
                NotifyPublic(NotificationType.Alert, msg);
            }
        }
        catch (Exception ex) { _ = ex.AutoDumpExceptionAsync(); }
    }

    private void MainWindow_Closed_Phase5(object sender, EventArgs e)
    {
        try { _hotkeys?.Dispose(); } catch { }
    }
}