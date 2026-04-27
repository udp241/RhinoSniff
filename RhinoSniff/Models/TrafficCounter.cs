using System.Threading;

namespace RhinoSniff.Models
{
    /// <summary>
    /// Thread-safe per-IP traffic counter. Tracks upload/download bytes and packet counts.
    /// Uses Interlocked for lock-free atomic increments from the capture thread.
    /// </summary>
    public class TrafficCounter
    {
        private long _uploadBytes;
        private long _downloadBytes;
        private long _uploadPackets;
        private long _downloadPackets;

        public long UploadBytes => Interlocked.Read(ref _uploadBytes);
        public long DownloadBytes => Interlocked.Read(ref _downloadBytes);
        public long UploadPackets => Interlocked.Read(ref _uploadPackets);
        public long DownloadPackets => Interlocked.Read(ref _downloadPackets);
        public long TotalPackets => UploadPackets + DownloadPackets;

        public void AddUpload(int bytes)
        {
            Interlocked.Add(ref _uploadBytes, bytes);
            Interlocked.Increment(ref _uploadPackets);
        }

        public void AddDownload(int bytes)
        {
            Interlocked.Add(ref _downloadBytes, bytes);
            Interlocked.Increment(ref _downloadPackets);
        }

        /// <summary>
        /// Format byte count to human-readable string (B, KB, MB, GB).
        /// </summary>
        public static string FormatBytes(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1048576) return $"{bytes / 1024.0:F1} KB";
            if (bytes < 1073741824) return $"{bytes / 1048576.0:F1} MB";
            return $"{bytes / 1073741824.0:F2} GB";
        }
    }
}
