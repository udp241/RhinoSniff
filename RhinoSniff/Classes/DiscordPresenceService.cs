using System;
using System.IO;
using RhinoSniff.Interfaces;
using RhinoSniff.Models;
using DiscordRPC;
using DiscordRPC.Logging;

namespace RhinoSniff.Classes
{
    public sealed class DiscordPresenceService : IDiscordPresenceService
    {
        private readonly DiscordPresenceConfiguration configuration;
        private DiscordRpcClient client;
        private readonly object _lock = new();

        public DiscordPresenceService(DiscordPresenceConfiguration configuration)
        {
            this.configuration = configuration;

            var appDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RhinoSniff");
            if (!Directory.Exists(appDir))
                Directory.CreateDirectory(appDir);
        }

        public RichPresence Presence { get; set; }

        public void CreateInstance()
        {
            lock (_lock)
            {
                if (client != null)
                {
                    try
                    {
                        if (client.IsInitialized && !client.IsDisposed)
                            client.Deinitialize();
                        if (!client.IsDisposed)
                            client.Dispose();
                    }
                    catch { }
                    client = null;
                }

                client = new DiscordRpcClient(configuration.ClientId.ToString(),
                    logger: new FileLogger(Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                        "RhinoSniff", "discord.log")));

                Presence = GetRichPresence();
            }
        }

        public RichPresence GetRichPresence()
        {
            return new RichPresence
            {
                Details = "Ready to capture",
                Timestamps = new Timestamps(DateTime.UtcNow),
                Assets = new Assets
                {
                    LargeImageKey = configuration.LargeImageKey,
                    LargeImageText = configuration.LargeImageText
                },
                Buttons = new[]
                {
                    new Button { Label = "Join Discord", Url = "https://discord.gg/nca" }
                }
            };
        }

        public void ResetPresence()
        {
            Presence = GetRichPresence();
        }

        public void Dispose()
        {
            lock (_lock)
            {
                try
                {
                    if (client != null && !client.IsDisposed)
                    {
                        if (client.IsInitialized)
                        {
                            client.ClearPresence();
                            client.Deinitialize();
                        }
                        client.Dispose();
                    }
                }
                catch { }
                client = null;
            }
        }

        public void ClearPresence()
        {
            lock (_lock)
            {
                if (client != null && client.IsInitialized && !client.IsDisposed)
                    client.ClearPresence();
            }
        }

        public void DeInitialize()
        {
            lock (_lock)
            {
                if (client == null || client.IsDisposed) return;
                if (!client.IsInitialized) return;

                try
                {
                    client.ClearPresence();
                    client.Deinitialize();
                }
                catch { }
            }
        }

        public void Initialize()
        {
            lock (_lock)
            {
                if (client == null || client.IsDisposed)
                    CreateInstance();

                if (!client.IsInitialized)
                    client.Initialize();

                SetPresence();
            }
        }

        public void ResetTimestamps()
        {
            Presence.WithTimestamps(null);
            SetPresence();
        }

        public void UpdateDetails(string details)
        {
            Presence.WithDetails(details);
            SetPresence();
        }

        public void UpdateState(string state)
        {
            Presence.WithState(state);
            SetPresence();
        }

        public void UpdateTimestamps()
        {
            Presence.WithTimestamps(new Timestamps(DateTime.UtcNow));
            SetPresence();
        }

        public void SetPresence()
        {
            lock (_lock)
            {
                if (client != null && client.IsInitialized && !client.IsDisposed)
                    client.SetPresence(Presence);
            }
        }
    }
}
