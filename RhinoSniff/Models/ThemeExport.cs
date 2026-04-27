namespace RhinoSniff.Models
{
    public class ThemeExport
    {
        public string Author { get; set; }

        public string BackgroundFileName { get; init; }

        public byte[] PictureBytes { get; init; }

        public Theme ThemeObject { get; init; }
    }
}