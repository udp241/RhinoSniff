using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Windows.Interop;
using RhinoSniff.Models;

namespace RhinoSniff.Classes
{
    /// <summary>
    /// Phase 5 — system-wide hotkeys via <c>RegisterHotKey</c> / <c>UnregisterHotKey</c>.
    ///
    /// Binds a <see cref="HotkeyAction"/> to a Win32 (modifiers, VK) pair. The manager owns
    /// an invisible <see cref="HwndSource"/> message sink — WM_HOTKEY messages route to
    /// <see cref="HotkeyFired"/> which MainWindow subscribes to.
    ///
    /// Each action gets a unique <c>id</c> passed to RegisterHotKey. Collisions (another app
    /// already owns the combo) surface as <see cref="RegisterResult.Conflict"/>.
    /// </summary>
    public class GlobalHotkeyManager : IDisposable
    {
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool RegisterHotKey(IntPtr hWnd, int id, uint fsModifiers, uint vk);

        [DllImport("user32.dll")]
        private static extern bool UnregisterHotKey(IntPtr hWnd, int id);

        private const int WmHotkey = 0x0312;
        private const int ErrorHotkeyAlreadyRegistered = 1409;

        public enum RegisterResult { Ok, Conflict, InvalidCombo, Error }

        private readonly HwndSource _source;
        private readonly Dictionary<HotkeyAction, int> _registered = new();
        private readonly Dictionary<int, HotkeyAction> _idToAction = new();
        private int _nextId = 0x9A00; // arbitrary base away from common app-id ranges
        private bool _disposed;

        /// <summary>
        /// Fires on the UI thread when a registered hotkey is pressed.
        /// </summary>
        public event Action<HotkeyAction> HotkeyFired;

        public GlobalHotkeyManager()
        {
            // Message-only window (HWND_MESSAGE = -3) — not visible, not in z-order,
            // receives WM_HOTKEY just fine.
            var parameters = new HwndSourceParameters("RhinoSniffHotkeySink")
            {
                WindowStyle = 0,
                ExtendedWindowStyle = 0,
                ParentWindow = new IntPtr(-3)
            };
            _source = new HwndSource(parameters);
            _source.AddHook(WndProc);
        }

        private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
        {
            if (msg == WmHotkey)
            {
                var id = wParam.ToInt32();
                if (_idToAction.TryGetValue(id, out var action))
                {
                    try { HotkeyFired?.Invoke(action); }
                    catch (Exception e) { _ = e.AutoDumpExceptionAsync(); }
                    handled = true;
                }
            }
            return IntPtr.Zero;
        }

        /// <summary>
        /// Register (or re-register) a binding for an action. Unregisters any existing binding
        /// for the same action first. <paramref name="binding"/> may be <c>null</c> or unset,
        /// in which case this is effectively just an unregister.
        /// </summary>
        public RegisterResult Register(HotkeyAction action, HotkeyBinding binding)
        {
            Unregister(action);
            if (binding == null || !binding.IsSet) return RegisterResult.Ok;
            if (binding.Modifiers == 0) return RegisterResult.InvalidCombo; // require at least one modifier

            var id = _nextId++;
            if (!RegisterHotKey(_source.Handle, id, binding.Modifiers, binding.Vk))
            {
                var err = Marshal.GetLastWin32Error();
                return err == ErrorHotkeyAlreadyRegistered
                    ? RegisterResult.Conflict
                    : RegisterResult.Error;
            }
            _registered[action] = id;
            _idToAction[id] = action;
            return RegisterResult.Ok;
        }

        public void Unregister(HotkeyAction action)
        {
            if (!_registered.TryGetValue(action, out var id)) return;
            UnregisterHotKey(_source.Handle, id);
            _registered.Remove(action);
            _idToAction.Remove(id);
        }

        public void UnregisterAll()
        {
            foreach (var id in _registered.Values) UnregisterHotKey(_source.Handle, id);
            _registered.Clear();
            _idToAction.Clear();
        }

        /// <summary>
        /// Apply all bindings from Settings.Hotkeys. Returns a list of (action, result) for
        /// any that failed to register so the UI can surface conflicts.
        /// </summary>
        public List<(HotkeyAction Action, RegisterResult Result)> ApplyFromSettings()
        {
            var failures = new List<(HotkeyAction, RegisterResult)>();
            UnregisterAll();
            var map = Globals.Settings?.Hotkeys;
            if (map == null) return failures;
            foreach (var kv in map)
            {
                if (kv.Value == null || !kv.Value.IsSet) continue;
                var r = Register(kv.Key, kv.Value);
                if (r != RegisterResult.Ok) failures.Add((kv.Key, r));
            }
            return failures;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            UnregisterAll();
            _source?.RemoveHook(WndProc);
            _source?.Dispose();
        }
    }
}
