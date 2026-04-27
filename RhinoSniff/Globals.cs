using RhinoSniff.Models;
using SimpleInjector;

namespace RhinoSniff
{
    public static class Globals
    {
        public static readonly Container Container = new();

        public static Settings Settings;
    }
}