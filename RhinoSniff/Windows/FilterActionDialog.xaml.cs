using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using RhinoSniff.Models;

namespace RhinoSniff.Windows
{
    /// <summary>
    /// Highlight/Discard/Remove dialog for filter cards. Hosted in MainWindow's
    /// FilterModalRoot overlay (same pattern as CreateFilterWizard) so it darkens
    /// the full window and supports click-outside-to-close.
    ///
    /// Result: returned via <see cref="Result"/> after <see cref="Completed"/> fires.
    /// "remove" = user clicked Remove Filter. FilterAction = user clicked Apply
    /// with that action selected. null = user cancelled.
    /// </summary>
    public partial class FilterActionDialog : UserControl
    {
        private FilterAction _selected;
        private readonly bool _isActiveAtOpen;

        public object Result { get; private set; }
        public event EventHandler Completed;
        public event EventHandler Cancelled;

        public FilterActionDialog(string title, bool isActive, FilterAction currentAction)
        {
            InitializeComponent();

            TitleText.Text = title ?? "";
            _selected = currentAction;
            _isActiveAtOpen = isActive;

            RemoveBtn.Visibility = isActive ? Visibility.Visible : Visibility.Collapsed;
            UpdateSelectionVisual();
        }

        private void Highlight_Click(object sender, MouseButtonEventArgs e)
        {
            _selected = FilterAction.Highlight;
            UpdateSelectionVisual();
        }

        private void Discard_Click(object sender, MouseButtonEventArgs e)
        {
            _selected = FilterAction.Discard;
            UpdateSelectionVisual();
        }

        private void UpdateSelectionVisual()
        {
            // Selected card gets AccentBlue border (blue "selected" ring).
            // Non-selected cards fall back to CardBorder via SetResourceReference so theme swap still works.
            if (_selected == FilterAction.Highlight)
            {
                HighlightCard.SetResourceReference(Border.BorderBrushProperty, "AccentBlue");
                HighlightCard.BorderThickness = new Thickness(2);
                DiscardCard.SetResourceReference(Border.BorderBrushProperty, "CardBorder");
                DiscardCard.BorderThickness = new Thickness(1);
            }
            else
            {
                DiscardCard.SetResourceReference(Border.BorderBrushProperty, "AccentBlue");
                DiscardCard.BorderThickness = new Thickness(2);
                HighlightCard.SetResourceReference(Border.BorderBrushProperty, "CardBorder");
                HighlightCard.BorderThickness = new Thickness(1);
            }
        }

        private void Apply_Click(object sender, RoutedEventArgs e)
        {
            Result = _selected;
            Completed?.Invoke(this, EventArgs.Empty);
        }

        private void Remove_Click(object sender, RoutedEventArgs e)
        {
            Result = "remove";
            Completed?.Invoke(this, EventArgs.Empty);
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            Result = null;
            Cancelled?.Invoke(this, EventArgs.Empty);
        }
    }
}
