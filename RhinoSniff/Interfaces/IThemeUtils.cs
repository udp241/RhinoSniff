using RhinoSniff.Models;
using System.Threading.Tasks;

namespace RhinoSniff.Interfaces
{
    public interface IThemeUtils
    {
        Task ExportTheme(string path);

        Task ImportTheme(string path);

        bool IsImage(string filename);

        MsgBox.MsgBoxResult MsgBox(MsgBox m);

        void SwitchTheme(Theme colorObject);
    }
}