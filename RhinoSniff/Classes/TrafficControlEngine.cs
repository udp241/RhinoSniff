using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using RhinoSniff.Models;
using SharpDivert;

namespace RhinoSniff.Classes
{
    /// <summary>
    /// Traffic Control engine — uses WinDivert to intercept, match, and manipulate
    /// live network packets according to the configured rules.
    /// 
    /// Actions: Drop, Lag (delay), Throttle (rate limit), Reorder (shuffle), Duplicate.
    /// Each rule supports probability (0–100%) and burst mode (ON/OFF cycling).
    /// 
    /// REQUIRES: WinDivert.dll + WinDivert64.sys in the application directory.
    /// Download from https://reqrypt.org/windivert.html (v2.2).
    /// </summary>
    public sealed class TrafficControlEngine : IDisposable
    {
        // ── Configuration ─────────────────────────────────────────────────
        // B4 fix: was `readonly`, now reassignable so UpdateRules can swap atomically.
        // List<T> reference assignment is atomic in CLR; receive thread's foreach holds
        // its own enumerator on the old list which is never mutated, only replaced.
        private List<TrafficRule> _rules;
        private WinDivert _divert;
        private volatile bool _running;
        private Thread _receiveThread;

        // ── Stats (thread-safe via Interlocked) ───────────────────────────
        private long _processed, _dropped, _delayed, _reordered, _duplicated, _throttled;

        public long Processed => Interlocked.Read(ref _processed);
        public long Dropped => Interlocked.Read(ref _dropped);
        public long Delayed => Interlocked.Read(ref _delayed);
        public long Reordered => Interlocked.Read(ref _reordered);
        public long Duplicated => Interlocked.Read(ref _duplicated);
        public long Throttled => Interlocked.Read(ref _throttled);

        /// <summary>Fires periodically (~200ms) with updated stats.</summary>
        public event Action<long, long, long, long, long, long> StatsUpdated;
        private Timer _statsTimer;

        // ── Burst mode state per rule ─────────────────────────────────────
        // Was Dictionary<TrafficRule, BurstState>, safe only because all writes
        // happened in Start() before the receive thread started. UpdateRules now
        // writes from the UI thread during a live engine — must be concurrent (B6).
        private readonly ConcurrentDictionary<TrafficRule, BurstState> _burstStates = new();

        // ── Lag queue (deferred packet reinjection) ───────────────────────
        private readonly ConcurrentQueue<DeferredPacket> _lagQueue = new();
        private Timer _lagTimer;

        // ── Reorder buffer per rule ───────────────────────────────────────
        private readonly ConcurrentDictionary<TrafficRule, ConcurrentQueue<DeferredPacket>> _reorderBuffers = new();
        private Timer _reorderTimer;

        // ── Throttle token buckets per rule ────────────────────────────────
        private readonly ConcurrentDictionary<TrafficRule, TokenBucket> _throttleBuckets = new();
        // B1 fix: was a single shared ConcurrentQueue<DeferredPacket> _throttleQueue,
        // which let two throttle rules consume each other's bucket budget on drain
        // (the drain iterated all buckets looking for any with capacity). Now per-rule
        // queues so each rule's overflow only consumes its own bucket.
        private readonly ConcurrentDictionary<TrafficRule, ConcurrentQueue<DeferredPacket>> _throttleQueues = new();
        private Timer _throttleTimer;

        // ── Random for probability ────────────────────────────────────────
        private readonly ThreadLocal<Random> _rng = new(() => new Random());

        // ══════════════════════════════════════════════════════════════════
        // Construction
        // ══════════════════════════════════════════════════════════════════

        public TrafficControlEngine(List<TrafficRule> rules)
        {
            if (rules == null) throw new ArgumentNullException(nameof(rules));
            // Defensive copy — caller (TC view) holds the live Settings list and may mutate
            // it after Start. UpdateRules is the supported way to push new rules in.
            _rules = new List<TrafficRule>(rules);
        }

        // ══════════════════════════════════════════════════════════════════
        // Start / Stop
        // ══════════════════════════════════════════════════════════════════

        public void Start()
        {
            if (_running) return;
            _running = true;

            // Reset stats
            _processed = _dropped = _delayed = _reordered = _duplicated = _throttled = 0;

            // Init burst timers
            foreach (var rule in _rules.Where(r => r.Enabled && r.BurstEnabled))
                _burstStates[rule] = new BurstState(rule.BurstOnMs, rule.BurstOffMs);

            // Init throttle buckets
            foreach (var rule in _rules.Where(r => r.Enabled && r.Action == TrafficAction.Throttle))
                _throttleBuckets[rule] = new TokenBucket(rule.RateKbps);

            // Open WinDivert — capture all IPv4 traffic at network layer
            _divert = new WinDivert("ip", WinDivert.Layer.Network, 0, 0);

            // Start receive thread
            _receiveThread = new Thread(ReceiveLoop)
            {
                Name = "TrafficControl-Recv",
                IsBackground = true,
                Priority = ThreadPriority.AboveNormal
            };
            _receiveThread.Start();

            // Start lag drain timer (every 5ms for responsive delay release)
            _lagTimer = new Timer(_ => DrainLagQueue(), null, 0, 5);

            // Start reorder flush timer (every 20ms — rules can have windows as short as 10ms)
            _reorderTimer = new Timer(_ => FlushReorderBuffers(), null, 20, 20);

            // Start throttle drain timer (every 10ms)
            _throttleTimer = new Timer(_ => DrainThrottleQueue(), null, 0, 10);

            // Stats reporting timer
            _statsTimer = new Timer(_ => FireStats(), null, 200, 200);
        }

        public void Stop()
        {
            if (!_running) return;
            _running = false;

            _statsTimer?.Dispose();
            _lagTimer?.Dispose();
            _reorderTimer?.Dispose();
            _throttleTimer?.Dispose();

            try { _divert?.Dispose(); } catch { }
            _divert = null;

            // Drain any remaining queued packets (they'll be lost — acceptable on stop)
            while (_lagQueue.TryDequeue(out _)) { }
            // B1 collateral: drain per-rule throttle queues, not the removed shared one.
            foreach (var q in _throttleQueues.Values)
                while (q.TryDequeue(out _)) { }
            _throttleQueues.Clear();
            _reorderBuffers.Clear();
            _burstStates.Clear();
            _throttleBuckets.Clear();

            // Wait for receive thread to exit
            _receiveThread?.Join(2000);
            _receiveThread = null;

            FireStats();
        }

        public void Dispose() => Stop();

        /// <summary>
        /// B4: hot-swap the rule set on a running engine so newly-added/edited/deleted/moved
        /// rules take effect without a Stop+Start. Safe to call from the UI thread while the
        /// receive thread is processing — `_rules` field is reassigned atomically (CLR ref
        /// assignment), and the receive thread's foreach holds an enumerator on the prior
        /// list which is never mutated, only replaced. New rules get their burst state and
        /// throttle bucket initialized here so the very next packet matches correctly.
        /// No-op if engine is stopped (caller will pass the new rules to Start instead).
        /// </summary>
        public void UpdateRules(List<TrafficRule> rules)
        {
            if (rules == null) return;
            // Defensive copy so caller mutations don't bleed into the engine snapshot.
            var snapshot = new List<TrafficRule>(rules);

            // Pre-init burst state + throttle bucket for any new rules we haven't seen.
            // Existing entries are left alone so in-flight burst phase / token bucket
            // refill state isn't reset by an unrelated rule add.
            foreach (var rule in snapshot.Where(r => r.Enabled && r.BurstEnabled))
                _burstStates.GetOrAdd(rule, r => new BurstState(r.BurstOnMs, r.BurstOffMs));
            foreach (var rule in snapshot.Where(r => r.Enabled && r.Action == TrafficAction.Throttle))
                _throttleBuckets.GetOrAdd(rule, r => new TokenBucket(r.RateKbps));

            // Atomic ref swap — receive thread sees this on its next foreach.
            _rules = snapshot;
        }

        // ══════════════════════════════════════════════════════════════════
        // Receive Loop (hot path — must be fast)
        // ══════════════════════════════════════════════════════════════════

        private void ReceiveLoop()
        {
            var recvBuf = new byte[WinDivert.MTUMax];
            var addrBuf = new WinDivertAddress[1];

            while (_running)
            {
                try
                {
                    var (recvLen, addrLen) = _divert.RecvEx(recvBuf.AsSpan(), addrBuf.AsSpan());
                    if (recvLen == 0) continue;

                    Interlocked.Increment(ref _processed);

                    var packetData = new byte[recvLen];
                    Buffer.BlockCopy(recvBuf, 0, packetData, 0, (int)recvLen);
                    var addr = addrBuf[0];

                    // Parse packet to extract matching fields
                    var info = ParsePacket(packetData, addr);

                    // Find first matching enabled rule
                    TrafficRule matched = null;
                    foreach (var rule in _rules)
                    {
                        if (!rule.Enabled) continue;
                        if (Matches(rule, info))
                        {
                            matched = rule;
                            break;
                        }
                    }

                    if (matched == null)
                    {
                        // No match — reinject immediately
                        Reinject(packetData, addr);
                        continue;
                    }

                    // Check burst mode — if in OFF phase, pass through
                    if (matched.BurstEnabled && _burstStates.TryGetValue(matched, out var bs) && !bs.IsActive)
                    {
                        Reinject(packetData, addr);
                        continue;
                    }

                    // Check probability
                    if (matched.Probability < 100 && _rng.Value.Next(100) >= matched.Probability)
                    {
                        Reinject(packetData, addr);
                        continue;
                    }

                    // Apply action
                    switch (matched.Action)
                    {
                        case TrafficAction.Drop:
                            Interlocked.Increment(ref _dropped);
                            // Don't reinject — packet is dropped
                            break;

                        case TrafficAction.Lag:
                            Interlocked.Increment(ref _delayed);
                            // Apply delay + optional ±jitter
                            int delayMs = matched.DelayMs;
                            if (matched.JitterMs > 0)
                            {
                                int jitter = _rng.Value.Next(-matched.JitterMs, matched.JitterMs + 1);
                                delayMs = Math.Max(0, delayMs + jitter);
                            }
                            _lagQueue.Enqueue(new DeferredPacket(packetData, addr,
                                Environment.TickCount64 + delayMs));
                            break;

                        case TrafficAction.Throttle:
                            Interlocked.Increment(ref _throttled);
                            if (_throttleBuckets.TryGetValue(matched, out var bucket) && bucket.TryConsume(packetData.Length))
                            {
                                // Within rate limit — reinject immediately
                                Reinject(packetData, addr);
                            }
                            else
                            {
                                // B1: queue into THIS rule's queue, not a shared one.
                                var ruleQueue = _throttleQueues.GetOrAdd(matched, _ => new ConcurrentQueue<DeferredPacket>());
                                ruleQueue.Enqueue(new DeferredPacket(packetData, addr,
                                    Environment.TickCount64 + 10)); // retry in 10ms
                            }
                            break;

                        case TrafficAction.Reorder:
                            // ReorderPercent: chance this packet gets buffered for shuffle vs passes through immediately
                            if (matched.ReorderPercent >= 100 || _rng.Value.Next(100) < matched.ReorderPercent)
                            {
                                Interlocked.Increment(ref _reordered);
                                var buf = _reorderBuffers.GetOrAdd(matched, _ => new ConcurrentQueue<DeferredPacket>());
                                // ReleaseAt encodes when this rule's buffer should next flush
                                buf.Enqueue(new DeferredPacket(packetData, addr,
                                    Environment.TickCount64 + matched.ReorderWindowMs));
                            }
                            else
                            {
                                Reinject(packetData, addr);
                            }
                            break;

                        case TrafficAction.Duplicate:
                            // Always send original
                            Reinject(packetData, addr);
                            // DuplicatePercent: chance to also send a duplicate copy
                            if (matched.DuplicatePercent >= 100 || _rng.Value.Next(100) < matched.DuplicatePercent)
                            {
                                Interlocked.Increment(ref _duplicated);
                                var copy = new byte[packetData.Length];
                                Buffer.BlockCopy(packetData, 0, copy, 0, packetData.Length);
                                if (matched.DuplicateDelayMs > 0)
                                {
                                    // Queue the duplicate with delay
                                    _lagQueue.Enqueue(new DeferredPacket(copy, addr,
                                        Environment.TickCount64 + matched.DuplicateDelayMs));
                                }
                                else
                                {
                                    Reinject(copy, addr);
                                }
                            }
                            break;
                    }
                }
                catch (ObjectDisposedException)
                {
                    // Handle closed during RecvEx — normal on Stop()
                    break;
                }
                catch (Exception)
                {
                    // Swallow transient errors to keep the loop alive
                    if (!_running) break;
                }
            }
        }

        // ══════════════════════════════════════════════════════════════════
        // Packet Parsing
        // ══════════════════════════════════════════════════════════════════

        private struct PacketInfo
        {
            public uint SrcIp;
            public uint DstIp;
            public string SrcIpStr;
            public string DstIpStr;
            public byte Protocol; // 6=TCP, 17=UDP
            public ushort SrcPort;
            public ushort DstPort;
            public bool Outbound;
        }

        private static PacketInfo ParsePacket(byte[] data, WinDivertAddress addr)
        {
            var info = new PacketInfo { Outbound = addr.Outbound };

            if (data.Length < 20) return info; // too short for IPv4

            // IPv4 header (we filtered "ip" so this is always IPv4)
            byte ihl = (byte)((data[0] & 0x0F) * 4);
            info.Protocol = data[9];
            info.SrcIp = (uint)(data[12] << 24 | data[13] << 16 | data[14] << 8 | data[15]);
            info.DstIp = (uint)(data[16] << 24 | data[17] << 16 | data[18] << 8 | data[19]);
            info.SrcIpStr = $"{data[12]}.{data[13]}.{data[14]}.{data[15]}";
            info.DstIpStr = $"{data[16]}.{data[17]}.{data[18]}.{data[19]}";

            // TCP (6) or UDP (17) header — both have src/dst port at same offsets
            if ((info.Protocol == 6 || info.Protocol == 17) && data.Length >= ihl + 4)
            {
                info.SrcPort = (ushort)(data[ihl] << 8 | data[ihl + 1]);
                info.DstPort = (ushort)(data[ihl + 2] << 8 | data[ihl + 3]);
            }

            return info;
        }

        // ══════════════════════════════════════════════════════════════════
        // Rule Matching
        // ══════════════════════════════════════════════════════════════════

        private bool Matches(TrafficRule rule, PacketInfo pkt)
        {
            // Protocol check
            if (rule.Protocol == TrafficProtocol.TCP && pkt.Protocol != 6) return false;
            if (rule.Protocol == TrafficProtocol.UDP && pkt.Protocol != 17) return false;

            // Direction check
            if (rule.Direction == TrafficDirection.Inbound && pkt.Outbound) return false;
            if (rule.Direction == TrafficDirection.Outbound && !pkt.Outbound) return false;

            // Target check
            switch (rule.TargetMode)
            {
                case TrafficTargetMode.AllTraffic:
                    break; // matches everything

                case TrafficTargetMode.SpecificIPs:
                    if (rule.TargetIPs == null || rule.TargetIPs.Count == 0) return false;
                    // Match if src OR dst is in the target list
                    bool ipMatch = false;
                    foreach (var ip in rule.TargetIPs)
                    {
                        if (ip == pkt.SrcIpStr || ip == pkt.DstIpStr) { ipMatch = true; break; }
                    }
                    if (!ipMatch) return false;
                    break;

                case TrafficTargetMode.Filter:
                    if (!MatchesFilter(rule.FilterPreset, pkt)) return false;
                    break;
            }

            // Port check (if ports specified)
            if (rule.Ports != null && rule.Ports.Count > 0)
            {
                bool portMatch = false;
                foreach (var pe in rule.Ports)
                {
                    if (pe.Contains(pkt.SrcPort) || pe.Contains(pkt.DstPort))
                    { portMatch = true; break; }
                }
                if (!portMatch) return false;
            }

            return true;
        }

        /// <summary>
        /// Match a packet against a FilterPreset by checking the filter's known ports/protocol.
        /// Uses the same port ranges defined in FilterRegistry.
        /// </summary>
        private static bool MatchesFilter(FilterPreset preset, PacketInfo pkt)
        {
            // Get the meta for port/protocol info from description
            // This is a simplified approach — we parse known port ranges from the filter descriptions
            // A more robust approach would store port ranges directly on FilterMeta
            var meta = FilterRegistry.Get(preset);
            if (meta.Protocol == FilterProtocol.Tcp && pkt.Protocol != 6) return false;
            if (meta.Protocol == FilterProtocol.Udp && pkt.Protocol != 17) return false;

            // For filter-based rules, we trust the filter matching — the filter system
            // already defines which ports/patterns identify each game.
            // Since we can't do DPI here (WinDivert gives raw packets, not labeled),
            // we match on the known port ranges encoded in the filter descriptions.
            var ports = GetFilterPorts(preset);
            if (ports == null || ports.Length == 0) return true; // no port info = match all

            foreach (var (lo, hi) in ports)
            {
                if ((pkt.SrcPort >= lo && pkt.SrcPort <= hi) ||
                    (pkt.DstPort >= lo && pkt.DstPort <= hi))
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Returns known port ranges for each filter preset.
        /// Mirrors the port definitions in FilterRegistry/PacketFilter.
        /// </summary>
        private static (ushort lo, ushort hi)[] GetFilterPorts(FilterPreset p) => p switch
        {
            FilterPreset.PSNParty => new[] { ((ushort)3478, (ushort)3480) },
            FilterPreset.XboxPartyBETA => new[] { ((ushort)3074, (ushort)3074) },
            FilterPreset.Discord => new[] { ((ushort)3478, (ushort)3480), ((ushort)19000, (ushort)19999) },
            FilterPreset.Fortnite => new[] { ((ushort)9000, (ushort)9100) },
            FilterPreset.ApexLegends => new[] { ((ushort)37000, (ushort)40000) },
            FilterPreset.PUBG => new[] { ((ushort)7080, (ushort)8000) },
            FilterPreset.CallOfDuty => new[] { ((ushort)3074, (ushort)3074), ((ushort)3478, (ushort)3480), ((ushort)4379, (ushort)4380), ((ushort)27000, (ushort)27031), ((ushort)28960, (ushort)28960) },
            FilterPreset.Valorant => new[] { ((ushort)5000, (ushort)5500), ((ushort)7000, (ushort)8000), ((ushort)8180, (ushort)8181) },
            FilterPreset.RainbowSixSiege => new[] { ((ushort)3074, (ushort)3074), ((ushort)3658, (ushort)3658), ((ushort)6015, (ushort)6015), ((ushort)6115, (ushort)6115), ((ushort)6150, (ushort)6150), ((ushort)10000, (ushort)10099) },
            FilterPreset.CSGO => new[] { ((ushort)27000, (ushort)27036) },
            FilterPreset.Overwatch => new[] { ((ushort)26000, (ushort)26600), ((ushort)6250, (ushort)6250) },
            FilterPreset.Battlefield => new[] { ((ushort)3659, (ushort)3659), ((ushort)14000, (ushort)14016), ((ushort)18000, (ushort)18000), ((ushort)21000, (ushort)21999), ((ushort)22990, (ushort)24000), ((ushort)25200, (ushort)25300) },
            FilterPreset.Halo => new[] { ((ushort)3074, (ushort)3075) },
            FilterPreset.Destiny => new[] { ((ushort)3074, (ushort)3074), ((ushort)3097, (ushort)3097), ((ushort)3480, (ushort)3480) },
            FilterPreset.GTAOnline => new[] { ((ushort)6672, (ushort)6672), ((ushort)61455, (ushort)61458) },
            FilterPreset.RDR2Online => new[] { ((ushort)6672, (ushort)6672), ((ushort)61455, (ushort)61458) },
            FilterPreset.Rust => new[] { ((ushort)28015, (ushort)28016), ((ushort)28083, (ushort)28083) },
            FilterPreset.ARK => new[] { ((ushort)7777, (ushort)7778), ((ushort)27015, (ushort)27016) },
            FilterPreset.DayZ => new[] { ((ushort)2302, (ushort)2305), ((ushort)27016, (ushort)27016) },
            FilterPreset.Minecraft => new[] { ((ushort)19132, (ushort)19133) },
            FilterPreset.RocketLeague => new[] { ((ushort)7000, (ushort)9000) },
            FilterPreset.FIFA => new[] { ((ushort)3659, (ushort)3659), ((ushort)9000, (ushort)9999), ((ushort)14000, (ushort)14016) },
            FilterPreset.NBA2K => new[] { ((ushort)3074, (ushort)3074), ((ushort)5000, (ushort)5500), ((ushort)3478, (ushort)3480) },
            FilterPreset.DeadByDaylight => new[] { ((ushort)27000, (ushort)27200), ((ushort)8010, (ushort)8400) },
            FilterPreset.SeaOfThieves => new[] { ((ushort)3074, (ushort)3074), ((ushort)3478, (ushort)3480) },
            FilterPreset.RecRoom => new[] { ((ushort)5056, (ushort)5056) },
            FilterPreset.Tekken => new[] { ((ushort)3074, (ushort)3074) },
            FilterPreset.MortalKombat => new[] { ((ushort)3074, (ushort)3074) },
            FilterPreset.uTorrent => null, // signature-based, not port-based
            FilterPreset.GenericTorrentClient => null,
            FilterPreset.GTAVConsole => new[] { ((ushort)3074, (ushort)3074), ((ushort)6672, (ushort)6672), ((ushort)61455, (ushort)61458) },
            FilterPreset.TCP => null, // handled by protocol check
            FilterPreset.UDP => null,
            _ => null
        };

        // ══════════════════════════════════════════════════════════════════
        // Deferred Packet Processing
        // ══════════════════════════════════════════════════════════════════

        private void Reinject(byte[] data, WinDivertAddress addr)
        {
            try
            {
                var addrSpan = new WinDivertAddress[] { addr };
                _divert?.SendEx(data.AsSpan(), addrSpan.AsSpan());
            }
            catch { }
        }

        /// <summary>Drain lag queue — release packets whose delay has elapsed.</summary>
        private void DrainLagQueue()
        {
            if (!_running) return;
            var now = Environment.TickCount64;
            while (_lagQueue.TryPeek(out var pkt) && pkt.ReleaseAt <= now)
            {
                if (_lagQueue.TryDequeue(out pkt))
                    Reinject(pkt.Data, pkt.Address);
            }
        }

        /// <summary>Flush reorder buffers — release shuffled packets when a rule's window has elapsed.</summary>
        private void FlushReorderBuffers()
        {
            if (!_running) return;
            var now = Environment.TickCount64;
            foreach (var kvp in _reorderBuffers)
            {
                var queue = kvp.Value;
                if (queue.IsEmpty) continue;

                // Only flush if the oldest packet's release time has been reached
                if (!queue.TryPeek(out var head) || head.ReleaseAt > now) continue;

                // B2 fix: only drain packets whose individual window has expired.
                // Previous code drained the entire queue once the head was overdue,
                // which collapsed the reorder window — a packet enqueued 1ms ago
                // would flush right alongside one enqueued 100ms ago.
                var batch = new List<DeferredPacket>();
                while (queue.TryPeek(out var pkt) && pkt.ReleaseAt <= now)
                {
                    if (queue.TryDequeue(out pkt))
                        batch.Add(pkt);
                    else
                        break; // raced with another consumer (shouldn't happen — single timer)
                }

                if (batch.Count == 0) continue;
                if (batch.Count == 1)
                {
                    Reinject(batch[0].Data, batch[0].Address);
                    continue;
                }

                // Fisher-Yates shuffle
                var rng = _rng.Value;
                for (int i = batch.Count - 1; i > 0; i--)
                {
                    int j = rng.Next(i + 1);
                    (batch[i], batch[j]) = (batch[j], batch[i]);
                }
                foreach (var p in batch) Reinject(p.Data, p.Address);
            }
        }

        /// <summary>Drain throttle queues — release packets if their rule's bucket has refilled.</summary>
        private void DrainThrottleQueue()
        {
            if (!_running) return;
            var now = Environment.TickCount64;

            // B1 fix: drain each rule's queue using ONLY that rule's bucket. Previously
            // there was one shared queue and the drain looped over all buckets to find
            // any that could accept the packet — meaning rule A's overflow would be sent
            // by consuming rule B's budget, defeating per-rule rate limits entirely.
            foreach (var kvp in _throttleQueues)
            {
                var rule = kvp.Key;
                var queue = kvp.Value;
                if (queue.IsEmpty) continue;
                if (!_throttleBuckets.TryGetValue(rule, out var bucket)) continue;

                int attempts = 0;
                while (queue.TryPeek(out var pkt) && attempts++ < 50)
                {
                    if (pkt.ReleaseAt > now) break; // not ready yet
                    if (!bucket.TryConsume(pkt.Data.Length)) break; // no budget for this rule

                    if (queue.TryDequeue(out pkt))
                        Reinject(pkt.Data, pkt.Address);
                }
            }
        }

        private void FireStats()
        {
            StatsUpdated?.Invoke(Processed, Dropped, Delayed, Reordered, Duplicated, Throttled);
        }

        // ══════════════════════════════════════════════════════════════════
        // Inner Types
        // ══════════════════════════════════════════════════════════════════

        private readonly struct DeferredPacket
        {
            public readonly byte[] Data;
            public readonly WinDivertAddress Address;
            public readonly long ReleaseAt; // Environment.TickCount64

            public DeferredPacket(byte[] data, WinDivertAddress address, long releaseAt)
            {
                Data = data;
                Address = address;
                ReleaseAt = releaseAt;
            }
        }

        /// <summary>Simple ON/OFF burst cycling state.</summary>
        private sealed class BurstState
        {
            private readonly int _onMs, _offMs;
            private long _nextToggle;
            private bool _on = true;

            public BurstState(int onMs, int offMs)
            {
                _onMs = onMs;
                _offMs = offMs;
                _nextToggle = Environment.TickCount64 + onMs;
            }

            public bool IsActive
            {
                get
                {
                    var now = Environment.TickCount64;
                    if (now >= _nextToggle)
                    {
                        _on = !_on;
                        _nextToggle = now + (_on ? _onMs : _offMs);
                    }
                    return _on;
                }
            }
        }

        /// <summary>Token bucket rate limiter for throttle action.</summary>
        private sealed class TokenBucket
        {
            private readonly double _rateBytes; // bytes per ms (kbps / 8)
            private double _tokens;
            private readonly double _maxTokens;
            private long _lastRefill;

            public TokenBucket(int rateKbps)
            {
                _rateBytes = rateKbps * 1000.0 / 8.0 / 1000.0; // bytes per ms
                _maxTokens = Math.Max(rateKbps * 1000.0 / 8.0, 1500); // 1 second burst, min 1 MTU
                _tokens = _maxTokens;
                _lastRefill = Environment.TickCount64;
            }

            public bool TryConsume(int bytes)
            {
                Refill();
                if (_tokens >= bytes)
                {
                    _tokens -= bytes;
                    return true;
                }
                return false;
            }

            private void Refill()
            {
                var now = Environment.TickCount64;
                var elapsed = now - _lastRefill;
                if (elapsed <= 0) return;
                _tokens = Math.Min(_maxTokens, _tokens + elapsed * _rateBytes);
                _lastRefill = now;
            }
        }
    }
}
