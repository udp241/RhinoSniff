using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using RhinoSniff.Interfaces;
using RhinoSniff.Models;
using Newtonsoft.Json;

namespace RhinoSniff.Classes
{
    public static class Web
    {
        private static readonly HttpClient Client;
        private static readonly ConcurrentDictionary<string, TaskCompletionSource<GeolocationResponse>> _pending = new();
        private static readonly Timer _batchTimer;
        private static int _processingBatch;

        // ip-api.com batch endpoint: POST up to 100 IPs per request, way fewer rate limit hits
        private const string BatchUrl = "http://ip-api.com/batch?fields=66846719";
        private const int BatchSize = 100;
        private const int BatchIntervalMs = 1500;

        static Web()
        {
            // Use DohHttp's client so every geo lookup resolves via Cloudflare DoH instead of
            // the system resolver. This bypasses ip-api.com / ipapi.co / ipinfo.io blocks in the
            // hosts file (RhinoGPS / privacy sinkhole) on a per-process basis — other apps on
            // the machine still see 127.0.0.1 for those domains.
            Client = DohHttp.CreateClient(TimeSpan.FromSeconds(15));
            Client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("RhinoSniff",
                Assembly.GetCallingAssembly().GetName().Version?.ToString()));

            _batchTimer = new Timer(ProcessBatchCallback, null, BatchIntervalMs, BatchIntervalMs);
        }

        public static async Task<GeolocationResponse> IpLocationAsync(IPAddress ip)
        {
            try
            {
                if (ip == null) return null;
                var ipStr = ip.ToString();

                var geoCacheManager = Globals.Container.GetInstance<ICacheManager<List<GeolocationCache>>>();
                var geoCache = geoCacheManager.GetCache() ?? new List<GeolocationCache>();

                var cached = geoCache.FirstOrDefault(x => x.IpAddress == ipStr);
                if (cached != null) return cached;

                if (_pending.TryGetValue(ipStr, out var existingTcs))
                    return await existingTcs.Task;

                var tcs = new TaskCompletionSource<GeolocationResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
                if (!_pending.TryAdd(ipStr, tcs))
                {
                    if (_pending.TryGetValue(ipStr, out var raceTcs))
                        return await raceTcs.Task;
                    return null;
                }

                var timeoutTask = Task.Delay(TimeSpan.FromSeconds(30));
                var completed = await Task.WhenAny(tcs.Task, timeoutTask);
                if (completed == timeoutTask)
                {
                    _pending.TryRemove(ipStr, out _);
                    return null;
                }

                return await tcs.Task;
            }
            catch (Exception e)
            {
                await e.AutoDumpExceptionAsync();
                return null;
            }
        }

        private static async void ProcessBatchCallback(object state)
        {
            if (Interlocked.CompareExchange(ref _processingBatch, 1, 0) != 0)
                return;

            try
            {
                await ProcessBatch();
            }
            catch (Exception e)
            {
                _ = e.AutoDumpExceptionAsync();
            }
            finally
            {
                Interlocked.Exchange(ref _processingBatch, 0);
            }
        }

        private static async Task ProcessBatch()
        {
            if (_pending.IsEmpty) return;

            var batch = _pending.Keys.Take(BatchSize).ToList();
            if (batch.Count == 0) return;

            try
            {
                var requestItems = batch.Select(ip => new { query = ip }).ToList();
                var jsonPayload = JsonConvert.SerializeObject(requestItems);
                var content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

                using var response = await Client.PostAsync(BatchUrl, content);

                if (response.StatusCode == HttpStatusCode.Forbidden ||
                    response.StatusCode == (HttpStatusCode)429)
                {
                    await Task.Delay(TimeSpan.FromSeconds(10));
                    return;
                }

                if (!response.IsSuccessStatusCode)
                {
                    foreach (var ip in batch)
                        if (_pending.TryRemove(ip, out var tcs))
                            tcs.TrySetResult(null);
                    return;
                }

                var responseBody = await response.Content.ReadAsStringAsync();
                var results = JsonConvert.DeserializeObject<List<BatchGeoResponse>>(responseBody);

                if (results == null)
                {
                    foreach (var ip in batch)
                        if (_pending.TryRemove(ip, out var tcs))
                            tcs.TrySetResult(null);
                    return;
                }

                var geoCacheManager = Globals.Container.GetInstance<ICacheManager<List<GeolocationCache>>>();
                var geoCache = geoCacheManager.GetCache() ?? new List<GeolocationCache>();
                var cacheModified = false;

                foreach (var result in results)
                {
                    var ipStr = result.Query;
                    if (string.IsNullOrEmpty(ipStr)) continue;

                    GeolocationResponse geoResult = null;

                    if (result.Status == "success")
                    {
                        geoResult = result;

                        if (!geoCache.Any(x => x.IpAddress == ipStr))
                        {
                            var cacheEntry = new GeolocationCache { IpAddress = ipStr };
                            cacheEntry.ConstructFromGeolocationResponse(geoResult);
                            geoCache.Add(cacheEntry);
                            cacheModified = true;
                        }
                    }

                    if (_pending.TryRemove(ipStr, out var tcs))
                        tcs.TrySetResult(geoResult);
                }

                if (cacheModified)
                    geoCacheManager.WriteCache(geoCache);

                // Any batch IPs not in the response — resolve as null
                foreach (var ip in batch)
                    if (_pending.TryRemove(ip, out var tcs))
                        tcs.TrySetResult(null);
            }
            catch (TaskCanceledException)
            {
                foreach (var ip in batch)
                    if (_pending.TryRemove(ip, out var tcs))
                        tcs.TrySetResult(null);
            }
            catch (Exception e)
            {
                await e.AutoDumpExceptionAsync();
                foreach (var ip in batch)
                    if (_pending.TryRemove(ip, out var tcs))
                        tcs.TrySetResult(null);
            }
        }
    }

    public class BatchGeoResponse : GeolocationResponse
    {
        [JsonProperty("query")] public string Query { get; set; }
        [JsonProperty("status")] public string Status { get; set; }
    }
}
