using RhinoSniff.Interfaces;
using RhinoSniff.Models;
using System;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;

namespace RhinoSniff.Classes
{
    public class ExportDrawer : IExportDrawer
    {
        public async Task DrawTableForExport(BindingList<CaptureGrid> submittedDataTable, string submittedFilePath)
        {
            var table = new TableHandler();

            table.SetHeaders("IP address", "Port", "Protocol", "Country", "City", "State", "ISP", "Upload", "Download", "Packets", "Last Seen", "Packet Type", "Label");

            foreach (var row in submittedDataTable)
            {
                table.AddRow(row.IpAddress.ToString(), row.Port.ToString(), row.Protocol ?? "", row.Country, row.City, row.State, row.Isp, row.Upload ?? "", row.Download ?? "", row.Packets ?? "", row.LastSeenText ?? "", row.PacketType ?? "", row.Label ?? "");
            }

            await File.WriteAllTextAsync(submittedFilePath, $"RhinoSniff [version {Assembly.GetExecutingAssembly().GetRhinoSniffVersionString()} RELEASE OSS] capture results, exported at {DateTime.UtcNow} UTC\nTotal items: {submittedDataTable.Count}\n\n");
            await File.AppendAllTextAsync(submittedFilePath, table.ToString());
        }
    }
}