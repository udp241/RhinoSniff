using System.Threading.Tasks;
using RhinoSniff.Models;

namespace RhinoSniff.Interfaces
{
    internal interface IErrorLogging
    {
        Task<bool> WriteToLogAsync(string buffer, LogLevel logType);
    }
}