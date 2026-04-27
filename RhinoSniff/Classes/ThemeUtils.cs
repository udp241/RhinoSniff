using System;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using RhinoSniff.Interfaces;
using RhinoSniff.Models;
using RhinoSniff.Properties;
using RhinoSniff.Windows;
using MaterialDesignThemes.Wpf;
using Newtonsoft.Json;
using Theme = RhinoSniff.Models.Theme;

namespace RhinoSniff.Classes
{
    public class ThemeUtils : IThemeUtils
    {
        public async Task ExportTheme(string path)
        {
            var obj = new Theme
            {
                CustomColorBrush = SafeHex(Globals.Settings.HexColor), DarkMode = true,
                PrimaryColor = Globals.Settings.ColorType, SecondaryColor = Globals.Settings.ColorType
            };

            if (Globals.Settings.Background != "None")
            {
                var wpBytes =
                    await File.ReadAllBytesAsync(
                        Path.GetFullPath(Globals.Settings.Background)); // Reads all wallpaper bytes asynchronously

                var expObj1 = JsonConvert.SerializeObject(new ThemeExport
                {
                    ThemeObject = obj,
                    BackgroundFileName = Path.GetFileName(Globals.Settings.Background),
                    PictureBytes = wpBytes,
                    Author = Environment.UserName
                }, Formatting.None);

                await File.WriteAllTextAsync(path, await Security.EncryptThemeAsync(expObj1));
                return;
            }

            var expObj = JsonConvert.SerializeObject(new ThemeExport
            {
                ThemeObject = obj,
                Author = Environment.UserName
            }, Formatting.None);

            await File.WriteAllTextAsync(path, await Security.EncryptThemeAsync(expObj));
        }

        public async Task ImportTheme(string path)
        {
            var theme =
                JsonConvert.DeserializeObject<ThemeExport>(
                    await Security.DecryptThemeAsync(await File.ReadAllTextAsync(path)));
            if (theme == null) return;
            
            Globals.Settings.ColorType = theme.ThemeObject.PrimaryColor;
            if (theme.BackgroundFileName != null && theme.PictureBytes != null)
            {
                // SECURITY: Strip any directory components to prevent path traversal
                var safeFileName = Path.GetFileName(theme.BackgroundFileName);
                if (string.IsNullOrWhiteSpace(safeFileName) || safeFileName.Contains(".."))
                {
                    Globals.Settings.Background = "None";
                }
                else
                {
                    var imagesDir = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                        "RhinoSniff", "themes", "images");
                    if (!Directory.Exists(imagesDir))
                        Directory.CreateDirectory(imagesDir);
                    var imagePath = Path.Combine(imagesDir, safeFileName);
                    
                    // Verify the resolved path is still inside our images directory
                    var resolvedPath = Path.GetFullPath(imagePath);
                    var resolvedDir = Path.GetFullPath(imagesDir);
                    if (!resolvedPath.StartsWith(resolvedDir, StringComparison.OrdinalIgnoreCase))
                    {
                        Globals.Settings.Background = "None";
                    }
                    else
                    {
                        if (!File.Exists(imagePath))
                            await File.WriteAllBytesAsync(imagePath, theme.PictureBytes);
                        Globals.Settings.Background = imagePath;
                    }
                }
            }
            else
            {
                Globals.Settings.Background = "None";
            }

            Globals.Settings.HexColor = theme.ThemeObject.CustomColorBrush.ToHex();
            SwitchTheme(new Theme
            {
                CustomColorBrush = SafeHex(Globals.Settings.HexColor), DarkMode = Globals.Settings.DarkMode,
                PrimaryColor = Globals.Settings.ColorType, SecondaryColor = Globals.Settings.ColorType
            });
        }

        public bool IsImage(string filename)
        {
            try
            {
                _ = new BitmapImage(new Uri(filename));
            }
            catch (NotSupportedException)
            {
                return false;
            }

            return true;
        }

        public MsgBox.MsgBoxResult MsgBox(MsgBox m)
        {
            CustomMsgBox msgBox = null;
            var thread = new Thread(() =>
            {
                msgBox = new CustomMsgBox(m);
                msgBox.ShowDialog();
            });
            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
            thread.Join();
            return msgBox.Result;
        }

    private static Color SafeHex(string hex)
    {
        try
        {
            if (!string.IsNullOrEmpty(hex) && hex.StartsWith("#"))
                return (Color)ColorConverter.ConvertFromString(hex);
        }
        catch { }
        return Color.FromRgb(0, 137, 123); // default teal
    }

        public async void SwitchTheme(Theme colorObject)
        {
            try
            {
                var baseTheme = colorObject.DarkMode
                    ? MaterialDesignThemes.Wpf.Theme.Dark
                    : MaterialDesignThemes.Wpf.Theme.Light;
                switch (colorObject.PrimaryColor)
                {
                    case ColorType.Default:
                        ITheme defaultTheme3 = MaterialDesignThemes.Wpf.Theme.Create(baseTheme,
                            Color.FromRgb(0, 137, 123), Color.FromRgb(0, 105, 92));
                        Application.Current.Resources.SetTheme(defaultTheme3);
                        break;

                    case ColorType.Accent:
                        ITheme defaultTheme1 = MaterialDesignThemes.Wpf.Theme.Create(baseTheme,
                            SystemParameters.WindowGlassColor, SystemParameters.WindowGlassColor);
                        Application.Current.Resources.SetTheme(defaultTheme1);
                        break;

                    case ColorType.Custom:
                        ITheme defaultTheme2 = MaterialDesignThemes.Wpf.Theme.Create(baseTheme,
                            colorObject.CustomColorBrush, colorObject.CustomColorBrush);
                        Application.Current.Resources.SetTheme(defaultTheme2);
                        break;

                    default:
                        try
                        {
                            var pColor = (Color) ColorConverter.ConvertFromString(colorObject.PrimaryColor.ToString());
                            var sColor = (Color) ColorConverter.ConvertFromString(colorObject.SecondaryColor.ToString());
                            ITheme theme = MaterialDesignThemes.Wpf.Theme.Create(baseTheme, pColor, sColor);
                            Application.Current.Resources.SetTheme(theme);
                        }
                        catch
                        {
                            // Fallback to default teal
                            var fallback = Color.FromRgb(0, 137, 123);
                            ITheme theme = MaterialDesignThemes.Wpf.Theme.Create(baseTheme, fallback, fallback);
                            Application.Current.Resources.SetTheme(theme);
                        }
                        break;
                }
            }
            catch (Exception e)
            {
                await e.AutoDumpExceptionAsync();
            }
        }
    }
}