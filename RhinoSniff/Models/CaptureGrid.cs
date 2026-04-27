using System.ComponentModel;
using System.Net;
using MaterialDesignThemes.Wpf;

namespace RhinoSniff.Models;

/// <summary>Phase 7.1 Session 4: platform classification for source filtering.</summary>
public enum Platform { Unknown, Psn, Xbox }

public class CaptureGrid : INotifyPropertyChanged
{
    private string city;
    private string country;
    private PackIconKind ddosProtected;
    private string flag;
    private IPAddress ipAddress;
    private string isp;
    private string label;
    private ushort port;
    private string protocol;
    private PackIconKind spoofed;
    private string state;
    private string firstSeen;
    private string upload;
    private string download;
    private string packets;

    public event PropertyChangedEventHandler PropertyChanged;

    public string City
    {
        get => city;
        set { city = value; OnPropertyChanged(nameof(City)); }
    }

    public string Country
    {
        get => country;
        set { country = value; OnPropertyChanged(nameof(Country)); }
    }

    public PackIconKind DDoSProtected
    {
        get => ddosProtected;
        set { ddosProtected = value; OnPropertyChanged(nameof(DDoSProtected)); }
    }

    public string Flag
    {
        get => flag;
        set { flag = value; OnPropertyChanged(nameof(Flag)); }
    }

    public IPAddress IpAddress
    {
        get => ipAddress;
        set { ipAddress = value; OnPropertyChanged(nameof(IpAddress)); }
    }

    public string Isp
    {
        get => isp;
        set { isp = value; OnPropertyChanged(nameof(Isp)); }
    }

    public string Label
    {
        get => label;
        set { label = value; OnPropertyChanged(nameof(Label)); }
    }

    public ushort Port
    {
        get => port;
        set { port = value; OnPropertyChanged(nameof(Port)); }
    }

    public string Protocol
    {
        get => protocol;
        set { protocol = value; OnPropertyChanged(nameof(Protocol)); }
    }

    public PackIconKind Spoofed
    {
        get => spoofed;
        set { spoofed = value; OnPropertyChanged(nameof(Spoofed)); }
    }

    public string State
    {
        get => state;
        set { state = value; OnPropertyChanged(nameof(State)); }
    }

    public string FirstSeen
    {
        get => firstSeen;
        set { firstSeen = value; OnPropertyChanged(nameof(FirstSeen)); }
    }

    public string Upload
    {
        get => upload;
        set { upload = value; OnPropertyChanged(nameof(Upload)); }
    }

    public string Download
    {
        get => download;
        set { download = value; OnPropertyChanged(nameof(Download)); }
    }

    public string Packets
    {
        get => packets;
        set { packets = value; OnPropertyChanged(nameof(Packets)); }
    }

    private System.DateTime lastSeenTime = System.DateTime.Now;
    private string lastSeenText = "now";
    private string packetType = "";

    public System.DateTime LastSeenTime
    {
        get => lastSeenTime;
        set { lastSeenTime = value; OnPropertyChanged(nameof(LastSeenTime)); }
    }

    public string LastSeenText
    {
        get => lastSeenText;
        set { lastSeenText = value; OnPropertyChanged(nameof(LastSeenText)); }
    }

    public string PacketType
    {
        get => packetType;
        set { packetType = value; OnPropertyChanged(nameof(PacketType)); }
    }

    private double packetsBarWidth;
    /// <summary>
    /// Width (0-40px) of the inline packet-count bar in the Packets column,
    /// recomputed each tick by MainWindow.UpdateTrafficForList.
    /// </summary>
    public double PacketsBarWidth
    {
        get => packetsBarWidth;
        set { packetsBarWidth = value; OnPropertyChanged(nameof(PacketsBarWidth)); }
    }

    private bool geoFailed;
    /// <summary>
    /// True when IP geolocation lookup failed. Phase 2 grid shows red "Failed"
    /// text instead of the country/city cells when true.
    /// </summary>
    public bool GeoFailed
    {
        get => geoFailed;
        set { geoFailed = value; OnPropertyChanged(nameof(GeoFailed)); }
    }

    private bool ispDimmed;
    /// <summary>
    /// Phase 3: true when the row's ISP does NOT match any active ISP filter rule
    /// AND the behavior is Dim (not Hide). Row is still rendered, just faded.
    /// </summary>
    public bool IspDimmed
    {
        get => ispDimmed;
        set { ispDimmed = value; OnPropertyChanged(nameof(IspDimmed)); }
    }

    private Platform platform;
    /// <summary>
    /// Phase 7.1 Session 4: classified platform (PSN / XBOX / Unknown) used by the
    /// FilterSource pill row to filter the grid. Tagged once at AddToSource time
    /// based on port + ISP heuristics — never recomputed.
    /// </summary>
    public Platform Platform
    {
        get => platform;
        set { platform = value; OnPropertyChanged(nameof(Platform)); }
    }

    private void OnPropertyChanged(string propertyName)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
