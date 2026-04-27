using Newtonsoft.Json;

namespace RhinoSniff.Models
{
    /// <summary>
    /// Persisted hotkey binding. Win32 virtual-key codes (not <see cref="System.Windows.Input.Key"/>)
    /// because <c>RegisterHotKey</c> takes VKs directly. Modifiers are the Win32 MOD_* flags
    /// (ALT=1, CONTROL=2, SHIFT=4, WIN=8). Zero/default means "not set".
    /// </summary>
    public class HotkeyBinding
    {
        [JsonProperty("modifiers")] public uint Modifiers { get; set; }
        [JsonProperty("vk")] public uint Vk { get; set; }

        [JsonIgnore]
        public bool IsSet => Vk != 0;

        /// <summary>
        /// Human-readable label e.g. "Ctrl+Shift+F9". Returns "Not set" when unbound.
        /// </summary>
        public string Display()
        {
            if (!IsSet) return "Not set";
            var parts = new System.Collections.Generic.List<string>();
            if ((Modifiers & 2) != 0) parts.Add("Ctrl");
            if ((Modifiers & 4) != 0) parts.Add("Shift");
            if ((Modifiers & 1) != 0) parts.Add("Alt");
            if ((Modifiers & 8) != 0) parts.Add("Win");
            parts.Add(VkToString(Vk));
            return string.Join("+", parts);
        }

        private static string VkToString(uint vk) => vk switch
        {
            >= 0x30 and <= 0x39 => ((char)vk).ToString(),          // 0-9
            >= 0x41 and <= 0x5A => ((char)vk).ToString(),          // A-Z
            >= 0x70 and <= 0x87 => "F" + (vk - 0x6F),              // F1-F24
            0x08 => "Backspace",
            0x09 => "Tab",
            0x0D => "Enter",
            0x1B => "Escape",
            0x20 => "Space",
            0x21 => "PageUp",
            0x22 => "PageDown",
            0x23 => "End",
            0x24 => "Home",
            0x25 => "Left",
            0x26 => "Up",
            0x27 => "Right",
            0x28 => "Down",
            0x2D => "Insert",
            0x2E => "Delete",
            0xBA => ";",
            0xBB => "=",
            0xBC => ",",
            0xBD => "-",
            0xBE => ".",
            0xBF => "/",
            0xC0 => "`",
            0xDB => "[",
            0xDC => "\\",
            0xDD => "]",
            0xDE => "'",
            _ => $"VK_0x{vk:X2}"
        };
    }
}
