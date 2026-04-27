using RhinoSniff.Models;
using System.ComponentModel;
using System.Threading.Tasks;

namespace RhinoSniff.Interfaces
{
    public interface IExportDrawer
    {
        Task DrawTableForExport(BindingList<CaptureGrid> submittedDataTable, string submittedFilePath);
    }
}