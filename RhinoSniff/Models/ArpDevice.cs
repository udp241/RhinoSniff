using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;

namespace RhinoSniff.Models;

/// <summary>
/// Single ARP poison target. v2.9.0 multi-target rework — `ArpDevice.Targets`
/// holds 0..N of these; the engine poisons each one per cycle.
/// </summary>
public class ArpTarget
{
    public IPAddress Ip { get; set; }
    public PhysicalAddress Mac { get; set; }
}

public struct ArpDevice
{
    public bool IsNullRouted { init; get; }

    public IPAddress SourceLocalAddress { init; get; }

    public PhysicalAddress SourcePhysicalAddress { init; get; }

    /// <summary>
    /// LEGACY single-target fields. Kept for back-compat with restore-state code paths
    /// in ArpContent (Phase 4) which read `existing.TargetLocalAddress`. New code should
    /// use <see cref="Targets"/> which the engine actually iterates.
    /// </summary>
    public IPAddress TargetLocalAddress { get; init; }

    public PhysicalAddress TargetPhysicalAddress { init; get; }

    /// <summary>v2.9.0: multi-target list. Engine poisons each target per cycle.</summary>
    public List<ArpTarget> Targets { get; init; }
}