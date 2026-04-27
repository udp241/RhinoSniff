using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Windows;
using RhinoSniff.Classes;
using RhinoSniff.Interfaces;
using RhinoSniff.Models;
using SimpleInjector;

namespace RhinoSniff
{
    public partial class App : Application
    {
        public App()
        {
            // Global crash handler — catches ANY unhandled exception so it always logs
            DispatcherUnhandledException += (_, args) =>
            {
                try
                {
                    _ = args.Exception.AutoDumpExceptionAsync();
                }
                catch { }
                args.Handled = true; // Prevent app from crashing
            };
            AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            {
                if (args.ExceptionObject is Exception ex)
                {
                    try { _ = ex.AutoDumpExceptionAsync(); } catch { }
                }
            };

            Globals.Container.Register<IPacketFilter, PacketFilter>(Lifestyle.Singleton);
            Globals.Container.Register<IThemeUtils, ThemeUtils>(Lifestyle.Singleton);
            Globals.Container.RegisterSingleton<IDiscordPresenceService>(() => new DiscordPresenceService(
                new DiscordPresenceConfiguration
                {
                    ClientId = 1483613332522012864,
                    LargeImageKey = "main",
                    LargeImageText = $"RhinoSniff [version {Assembly.GetExecutingAssembly().GetName().Version}]"
                }));
            Globals.Container.Register<IExportDrawer, ExportDrawer>(Lifestyle.Singleton);
            Globals.Container.Register<IServerSettings, ServerSettings>(Lifestyle.Singleton);
            Globals.Container.Register<IErrorLogging, ErrorLogging>(Lifestyle.Singleton);
            Globals.Container.RegisterSingleton<ICacheManager<List<GeolocationCache>>>(() => new CacheManager<List<GeolocationCache>>(new CacheConfiguration
            {
                FilePath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "RhinoSniff", "geo.bin")
            }));
            Globals.Container.Register(() => new HttpClient(), Lifestyle.Singleton);

            Globals.Container.Verify();
            
            // Initialize default settings immediately so nothing NullRefs
            // before BootstrapWindow loads the real settings from disk.
            Globals.Settings = new Settings();
        }
    }
}
