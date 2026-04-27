using RhinoSniff.Models;
using System.Threading.Tasks;

namespace RhinoSniff.Interfaces
{
    public interface IServerSettings
    {
        Task GetSettingsAsync();

        Task<bool> UpdateSettingsAsync();
    }
}