using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media.Animation;
using RhinoSniff.Interfaces;
using RhinoSniff.Models;
using static RhinoSniff.Extensions;

namespace RhinoSniff.Windows
{
    public partial class BootstrapWindow : Window
    {
        private readonly Thread logoThread;

        private bool closeStoryBoardCompleted;

        private bool threadRunning = true;

        public BootstrapWindow()
        {
            InitializeComponent();
            Title = "RhinoSniff";
            logoThread = new Thread(async () => await Task.Run(PulsateLogo))
            {
                Name = "RhinoSniff-Logo-Thread",
                IsBackground = true,
                Priority = ThreadPriority.BelowNormal
            };
            logoThread.Start();
        }

        private async void DoWork()
        {
            try
            {
                // Load settings from disk BEFORE opening MainWindow
                await Globals.Container.GetInstance<IServerSettings>().GetSettingsAsync();
                
                await Adapter.InitAdapters();
                
                Dispatcher.Invoke(() =>
                {
                    // Apply persisted theme BEFORE MainWindow paints so the initial
                    // render already uses the correct Dark/Light tokens.
                    Classes.ThemeManager.ApplyTheme(Globals.Settings.DarkMode);
                    Classes.ThemeManager.ApplyAccent(Globals.Settings.AccentColorHex);
                    Classes.ThemeManager.ApplyFont(Globals.Settings.FontFamily);

                    MainWindow mainWindow1 = new();
                    mainWindow1.Show();
                    Close();
                });
            }
            catch (Exception e)
            {
                MessageBox.Show($"{Properties.Resources.GENERIC_EXCEPTION}\n\nWhat happened: {e}", "RhinoSniff",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                Environment.Exit(0);
            }
        }

        private async Task PulsateLogo()
        {
            await Dispatcher.InvokeAsync(async () =>
            {
                while (threadRunning)
                {
                    await Task.Delay(1000);
                    var pulsateLogo = FindResource("Pulsate") as BeginStoryboard;
                    pulsateLogo?.Storyboard.Begin();
                }
            });
        }

        private async void StopThread()
        {
            await Dispatcher.InvokeAsync(() =>
            {
                threadRunning = false;
                logoThread.Join();
            });
        }

        private void Storyboard_Completed(object sender, EventArgs e)
        {
            closeStoryBoardCompleted = true;
            StopThread();
            Close();
        }

        private void Window_Closing(object sender, CancelEventArgs e)
        {
            if (closeStoryBoardCompleted) return;
            
            var sb = FindResource("CloseAnim") as BeginStoryboard;
            sb?.Storyboard.Begin();
            e.Cancel = true;
        }

        private async void Window_Loaded(object sender, RoutedEventArgs e)
        {
            await Task.Run(DoWork);
        }
    }
}
