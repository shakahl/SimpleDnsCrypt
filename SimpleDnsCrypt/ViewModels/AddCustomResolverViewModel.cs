using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Reactive;
using System.Reactive.Linq;
using Caliburn.Micro;
using Reactive.Bindings;
using ReactiveUI;
using SimpleDnsCrypt.Utils;
using ReactiveCommand = ReactiveUI.ReactiveCommand;

namespace SimpleDnsCrypt.ViewModels
{
    [Export(typeof(AddCustomResolverViewModel))]
    public class AddCustomResolverViewModel : Screen
    {
        public ReactiveCommand<Unit, Unit> OkCommand { get; }
        public ReactiveCommand<Unit, Unit> CancelCommand { get; }
        public ReactiveProperty<string> Name { get; }

        public ReactiveProperty<string> Stamp { get; } = new ReactiveProperty<string>().SetValidateNotifyError(s =>
        {
            try
            {
                if (StampTools.Decode(s)?.IsValid ?? false)
                {
                    return null;
                }

                return "Failed to decode stamp";
            }
            catch (Exception e)
            {
                return e.Message;
            }
        });

        public HashSet<string> ExistingNames { get; set; } = new HashSet<string>();

        public AddCustomResolverViewModel()
        {
            Name = new ReactiveProperty<string>().SetValidateNotifyError(s => ExistingNames.Contains(s) ? $"Name {s} is already present in the server list" : null);
            OkCommand = ReactiveCommand.CreateFromTask(() => TryCloseAsync(true), Name.ObserveHasErrors.CombineLatest(Stamp.ObserveHasErrors, (a, b) => !a && !b));
            CancelCommand = ReactiveCommand.CreateFromTask(() => TryCloseAsync(false));
        }
    }
}
