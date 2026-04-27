using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using RhinoSniff.Classes;
using RhinoSniff.Models;
using RhinoSniff.Windows;

namespace RhinoSniff.Views
{
    public partial class IPStorage : UserControl
    {
        public class Row
        {
            public string Ip { get; set; }
            public string Comment { get; set; }
            public string CreatedDisplay { get; set; }
        }

        private readonly MainWindow _host;
        private readonly ObservableCollection<Row> _rows = new();
        private string _searchFilter = "";

        public IPStorage(MainWindow host)
        {
            _host = host;
            InitializeComponent();
            StorageGrid.ItemsSource = _rows;

            Loaded += async (_, _) =>
            {
                if (!IpStorageManager.Loaded)
                    await IpStorageManager.LoadAsync();
                Refresh();
            };

            Unloaded += (_, _) => IpStorageManager.Changed -= OnStoreChanged;
            IpStorageManager.Changed += OnStoreChanged;
        }

        private void OnStoreChanged()
        {
            if (!Dispatcher.CheckAccess())
            {
                Dispatcher.Invoke(Refresh);
                return;
            }
            Refresh();
        }

        private void Refresh()
        {
            _rows.Clear();
            var q = (_searchFilter ?? "").Trim();
            foreach (var e in IpStorageManager.Entries)
            {
                if (!string.IsNullOrEmpty(q))
                {
                    var haystack = (e.Ip + " " + e.Comment).ToLowerInvariant();
                    if (!haystack.Contains(q.ToLowerInvariant())) continue;
                }
                _rows.Add(new Row
                {
                    Ip = e.Ip,
                    Comment = e.Comment,
                    CreatedDisplay = e.CreatedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm")
                });
            }

            var total = IpStorageManager.Count;
            CountPillText.Text = total == 1 ? "1 ENTRY" : $"{total} ENTRIES";
            EmptyState.Visibility = _rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            StorageGrid.Visibility = _rows.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
        }

        private void Search_TextChanged(object sender, TextChangedEventArgs e)
        {
            _searchFilter = SearchBox.Text ?? "";
            Refresh();
        }

        private async void Add_Click(object sender, RoutedEventArgs e) => await AddFromInputs();

        private async void AddInputs_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) await AddFromInputs();
        }

        private async Task AddFromInputs()
        {
            var ip = (AddIpInput.Text ?? "").Trim();
            var comment = (AddCommentInput.Text ?? "").Trim();
            if (string.IsNullOrWhiteSpace(ip))
            {
                _host?.NotifyPublic(NotificationType.Alert, "Enter an IP address.");
                return;
            }
            if (!System.Net.IPAddress.TryParse(ip, out _))
            {
                _host?.NotifyPublic(NotificationType.Alert, "Invalid IP address.");
                return;
            }
            await IpStorageManager.AddAsync(ip, comment);
            AddIpInput.Text = string.Empty;
            AddCommentInput.Text = string.Empty;
            _host?.NotifyPublic(NotificationType.Info, $"Stored {ip}");
        }

        private void NewEntry_Click(object sender, RoutedEventArgs e)
        {
            AddIpInput.Focus();
        }

        private async void Refresh_Click(object sender, RoutedEventArgs e)
        {
            await IpStorageManager.LoadAsync();
            _host?.NotifyPublic(NotificationType.Info, "IP Storage reloaded.");
        }

        private async void Clear_Click(object sender, RoutedEventArgs e)
        {
            if (IpStorageManager.Count == 0) return;
            var result = MessageBox.Show(
                Window.GetWindow(this),
                $"Delete all {IpStorageManager.Count} stored IPs? This cannot be undone.",
                "Clear IP Storage",
                MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (result != MessageBoxResult.Yes) return;
            await IpStorageManager.ClearAsync();
            _host?.NotifyPublic(NotificationType.Info, "Cleared all stored IPs.");
        }

        private async void DeleteRow_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not FrameworkElement fe) return;
            var ip = fe.Tag as string;
            if (string.IsNullOrWhiteSpace(ip)) return;
            await IpStorageManager.DeleteAsync(ip);
        }

        private void EditRow_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not FrameworkElement fe) return;
            var ip = fe.Tag as string;
            if (string.IsNullOrWhiteSpace(ip)) return;
            var current = IpStorageManager.LookupComment(ip) ?? "";
            // Populate the top add-bar with the row's values. Clicking Add re-upserts with
            // the edited comment (AddAsync does upsert by IP). Keeps the UI consistent
            // without pulling in Microsoft.VisualBasic.Interaction.InputBox or building
            // a full modal editor for a single-field change.
            AddIpInput.Text = ip;
            AddCommentInput.Text = current;
            AddCommentInput.Focus();
            AddCommentInput.SelectAll();
            _host?.NotifyPublic(NotificationType.Info, $"Editing {ip} — update comment and click Add.");
        }
    }
}
