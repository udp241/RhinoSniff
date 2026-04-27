namespace RhinoSniff.Models
{
    /// <summary>
    /// What to do when a packet matches a filter preset.
    /// Highlight: matched packets appear in the Filtered Traffic tab (current default).
    /// Discard: matched packets are dropped from every view.
    /// </summary>
    public enum FilterAction
    {
        Highlight,
        Discard
    }
}
