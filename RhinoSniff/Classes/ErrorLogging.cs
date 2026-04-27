using System;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using RhinoSniff.Interfaces;
using RhinoSniff.Models;
using RhinoSniff.Properties;

namespace RhinoSniff.Classes
{
    public class ErrorLogging : IErrorLogging
    {
        private readonly string logfile;

        public ErrorLogging()
        {
            logfile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RhinoSniff",
                "logfile.log");
        }

        public async Task<bool> CreateLogAsync()
        {
            try
            {
                if (File.Exists(logfile)) File.Delete(logfile);

                await File.AppendAllTextAsync(logfile,
                    $"[{DateTime.Now}] [INFO]: RhinoSniff v{Assembly.GetExecutingAssembly().GetRhinoSniffVersion()} [{Resources.APP_STAGE}]\r\n[{DateTime.Now}] [INFO]: Created a new log file\r\n",
                    Encoding.UTF8);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public async Task<bool> WriteToLogAsync(string buffer, LogLevel logType)
        {
            try
            {
                if (!File.Exists(logfile)) await CreateLogAsync();
                await File.AppendAllTextAsync(logfile, $"[{DateTime.Now}] [{logType}]: {buffer}\r\n", Encoding.UTF8);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}