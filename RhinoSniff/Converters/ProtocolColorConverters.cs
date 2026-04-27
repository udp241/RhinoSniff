using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace RhinoSniff.Converters
{
    public class ProtocolToBackgroundConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            var proto = (value as string)?.ToUpperInvariant() ?? "";
            return proto switch
            {
                "TCP" => new SolidColorBrush(Color.FromArgb(0x33, 0x42, 0xA5, 0xF5)),
                "UDP" => new SolidColorBrush(Color.FromArgb(0x33, 0x66, 0xBB, 0x6A)),
                _ => new SolidColorBrush(Color.FromArgb(0x33, 0x00, 0xBF, 0xA5))
            };
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotImplementedException();
    }

    public class ProtocolToForegroundConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            var proto = (value as string)?.ToUpperInvariant() ?? "";
            return proto switch
            {
                "TCP" => new SolidColorBrush(Color.FromRgb(0x42, 0xA5, 0xF5)),
                "UDP" => new SolidColorBrush(Color.FromRgb(0x66, 0xBB, 0x6A)),
                _ => new SolidColorBrush(Color.FromRgb(0x00, 0xBF, 0xA5))
            };
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotImplementedException();
    }
}
