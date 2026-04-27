using System;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using RhinoSniff.Models;
using MaterialDesignThemes.Wpf;

namespace RhinoSniff.Windows
{
    public partial class CustomMsgBox : Window
    {
        private bool closeStoryBoardCompleted;

        public CustomMsgBox(MsgBox messageBoxObject)
        {
            InitializeComponent();
            RhinoSniff.Classes.ThemeManager.StampWindowBorder(this);
            RhinoSniff.Classes.ThemeManager.HookBorderAutoHeal(this);
            RhinoSniff.Classes.BreathingBorderManager.Register(this);
            if (Globals.Settings?.Background != null && Globals.Settings.Background != "None")
            {
                try
                {
                    var fullPath = System.IO.Path.GetFullPath(Globals.Settings.Background);
                    if (System.IO.File.Exists(fullPath))
                    {
                        var uri = new Uri(fullPath);
                        if (uri.IsFile && !uri.IsUnc)
                        {
                            var bg = new BitmapImage();
                            bg.BeginInit();
                            bg.UriSource = uri;
                            bg.EndInit();
                            // Background image loaded but not assigned to any element;
                            // kept for potential future use (original code was the same).
                        }
                    }
                }
                catch (Exception)
                {
                    // Ignore background load failures in message boxes
                }
            }

            MsgBoxIco.Kind = messageBoxObject.Icon switch
            {
                MsgBox.MsgBoxIcon.Error => PackIconKind.ErrorOutline,
                MsgBox.MsgBoxIcon.Information => PackIconKind.InformationOutline,
                MsgBox.MsgBoxIcon.Question => PackIconKind.QuestionMarkCircleOutline,
                MsgBox.MsgBoxIcon.Success => PackIconKind.Check,
                MsgBox.MsgBoxIcon.Warning => PackIconKind.WarningBoxOutline,
                _ => MsgBoxIco.Kind
            };

            switch (messageBoxObject.Button)
            {
                case MsgBox.MsgBoxBtn.Ok:
                    OkButton.Visibility = Visibility.Visible;
                    break;

                case MsgBox.MsgBoxBtn.OkCancel:
                    OkButton.Visibility = Visibility.Visible;
                    CancelButton.Visibility = Visibility.Visible;
                    break;

                case MsgBox.MsgBoxBtn.RetryCancel:
                    RetryBtn.Visibility = Visibility.Visible;
                    CancelButton.Visibility = Visibility.Visible;
                    break;

                case MsgBox.MsgBoxBtn.YesNo:
                    YesButton.Visibility = Visibility.Visible;
                    NoButton.Visibility = Visibility.Visible;
                    break;

                case MsgBox.MsgBoxBtn.YesNoCancel:
                    YesButton.Visibility = Visibility.Visible;
                    NoButton.Visibility = Visibility.Visible;
                    CancelButton.Visibility = Visibility.Visible;
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }

            MsgBoxContent.Text = messageBoxObject.Message;
        }

        public MsgBox.MsgBoxResult Result { get; private set; }

        private void HandleButtonClicks(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn)
                Result = btn.Name switch
                {
                    "OKBtn" => MsgBox.MsgBoxResult.Ok,
                    "YesBtn" => MsgBox.MsgBoxResult.Yes,
                    "NoBtn" => MsgBox.MsgBoxResult.No,
                    "CancelBtn" => MsgBox.MsgBoxResult.Cancel,
                    "RetryBtn" => MsgBox.MsgBoxResult.Retry,
                    _ => Result
                };

            Close();
        }

        private void Storyboard_Completed(object sender, EventArgs e)
        {
            closeStoryBoardCompleted = true;
            Close();
        }

        private void Window_Closing(object sender, CancelEventArgs e)
        {
            if (closeStoryBoardCompleted) return;
            
            var sb = FindResource("CloseAnim") as BeginStoryboard;
            sb?.Storyboard.Begin();
            e.Cancel = true;
        }
    }
}