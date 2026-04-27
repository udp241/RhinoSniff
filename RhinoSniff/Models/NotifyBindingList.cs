using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;

namespace RhinoSniff.Models
{
    /// <summary>
    /// BindingList subclass that exposes per-item change notifications
    /// and supports column sorting for WPF DataGrid.
    /// </summary>
    public class NotifyBindingList<T> : BindingList<T>
    {
        private bool _isSorted;
        private PropertyDescriptor _sortProperty;
        private ListSortDirection _sortDirection;

        /// <summary>
        /// Notify the DataGrid that a specific row changed.
        /// This causes only that row to refresh, not the entire grid.
        /// </summary>
        public void NotifyItemChanged(int index)
        {
            if (index >= 0 && index < Count)
                OnListChanged(new ListChangedEventArgs(ListChangedType.ItemChanged, index));
        }

        protected override bool SupportsSortingCore => true;
        protected override bool IsSortedCore => _isSorted;
        protected override PropertyDescriptor SortPropertyCore => _sortProperty;
        protected override ListSortDirection SortDirectionCore => _sortDirection;

        protected override void ApplySortCore(PropertyDescriptor prop, ListSortDirection direction)
        {
            _sortProperty = prop;
            _sortDirection = direction;
            _isSorted = true;

            var items = new List<T>(Items);
            items.Sort((a, b) =>
            {
                var va = prop.GetValue(a);
                var vb = prop.GetValue(b);

                int result;
                if (va == null && vb == null)
                    result = 0;
                else if (va == null)
                    result = -1;
                else if (vb == null)
                    result = 1;
                else if (va is IComparable ca)
                    result = ca.CompareTo(vb);
                else
                    result = string.Compare(va.ToString(), vb.ToString(), StringComparison.OrdinalIgnoreCase);

                return direction == ListSortDirection.Descending ? -result : result;
            });

            var raiseEvents = RaiseListChangedEvents;
            RaiseListChangedEvents = false;
            try
            {
                ClearItems();
                foreach (var item in items)
                    Add(item);
            }
            finally
            {
                RaiseListChangedEvents = raiseEvents;
            }

            OnListChanged(new ListChangedEventArgs(ListChangedType.Reset, -1));
        }

        protected override void RemoveSortCore()
        {
            _isSorted = false;
            _sortProperty = null;
        }
    }
}
