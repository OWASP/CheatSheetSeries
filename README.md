[![NuGet Stats](https://img.shields.io/nuget/v/reactiveui.svg)](https://www.nuget.org/packages/reactiveui) [![Build Status](https://dev.azure.com/dotnet/ReactiveUI/_apis/build/status/ReactiveUI-CI)](https://dev.azure.com/dotnet/ReactiveUI/_build/latest?definitionId=11) 
 [![Code Coverage](https://codecov.io/gh/reactiveui/ReactiveUI/branch/master/graph/badge.svg)](https://codecov.io/gh/reactiveui/ReactiveUI) [![#yourfirstpr](https://img.shields.io/badge/first--timers--only-friendly-blue.svg)](https://reactiveui.net/contribute) 
[![Dependabot Status](https://api.dependabot.com/badges/status?host=github&repo=reactiveui/ReactiveUI)](https://dependabot.com)
<br>
<a href="https://www.nuget.org/packages/reactiveui">
        <img src="https://img.shields.io/nuget/dt/reactiveui.svg">
</a>
<a>
  Added something here
</a>
<a href="#backers">
        <img src="https://opencollective.com/reactiveui/backers/badge.svg">
</a>
<a href="#sponsors">
        <img src="https://opencollective.com/reactiveui/sponsors/badge.svg">
</a>
<a href="https://reactiveui.net/slack">
        <img src="https://img.shields.io/badge/chat-slack-blue.svg">
</a>
<br>
<br>
<a href="https://github.com/reactiveui/reactiveui">
  <img width="160" heigth="160" src="https://raw.githubusercontent.com/reactiveui/styleguide/master/logo/main.png">
</a>
<br>
<h1>What is ReactiveUI?</h1>

<a href="https://reactiveui.net/">ReactiveUI</a> is a composable, cross-platform model-view-viewmodel framework for all .NET platforms that is inspired by functional reactive programming which is a paradigm that allows you to <a href="https://www.youtube.com/watch?v=3HwEytvngXk">abstract mutable state away from your user interfaces and express the idea around a feature in one readable place</a> and improve the testability of your application. 

<a href="https://reactiveui.net/docs/getting-started/">🔨 Get Started</a> <a href="https://reactiveui.net/docs/getting-started/installation/">🛍 Install Packages</a> <a href="https://reactiveui.net/docs/resources/videos">🎞 Watch Videos</a> <a href="https://reactiveui.net/docs/resources/samples/">🎓 View Samples</a> <a href="https://reactiveui.net/slack">🎤 Discuss ReactiveUI</a>

<h2>Book</h2>
There has been an excellent <a href="https://kent-boogaart.com/you-i-and-reactiveui/">book</a> written by our Alumni maintainer Kent Boogart.
 
<h2>Introduction to Reactive Programming</h2>

Long ago, when computer programming first came to be, machines had to be programmed quite manually. If the technician entered the correct sequence of machine codes in the correct order, then the resulting program behavior would satisfy the business requirements. Instead of telling a computer how to do its job, which error-prone and relies too heavily on the infallibility of the programmer, why don't we just tell it what it's job is and let it figure the rest out?

ReactiveUI is inspired by the paradigm of Functional Reactive Programming, which allows you to model user input as a function that changes over time. This is super cool because it allows you to abstract mutable state away from your user interfaces and express the idea around a feature in one readable place whilst improving application testability. Reactive programming can look scary and complex at first glance, but the best way to describe reactive programming is to think of a spreadsheet:

![](https://reactiveui.net/docs/frp-excel.gif)

* Three cells, A, B, and C.
* C is defined as the sum of A and B.
* Whenever A or B changes, C reacts to update itself.

That's reactive programming: changes propagate throughout a system automatically. Welcome to the peanut butter and jelly of programming paradigms. For further information please watch the this video from the Xamarin Evolve conference - [Why You Should Be Building Better Mobile Apps with Reactive Programming](http://www.youtube.com/watch?v=DYEbUF4xs1Q) by Michael Stonis.

<h2>NuGet Packages</h2>

Install the following packages to start building your own ReactiveUI app. <b>Note:</b> some of the platform-specific packages are required. This means your app won't perform as expected until you install the packages properly. See the <a href="https://reactiveui.net/docs/getting-started/installation/">Installation</a> docs page for more info.

| Platform          | ReactiveUI Package                  | NuGet                | [Events][EventsDocs] Package            |
| ----------------- | ----------------------------------- | -------------------- | --------------------------------------- |
| .NET Standard     | [ReactiveUI][CoreDoc]               | [![CoreBadge]][Core] | None                                    |
|                   | [ReactiveUI.Fody][FodyDoc]          | [![FodyBadge]][Fody] | None                                    |
| Unit Testing      | [ReactiveUI.Testing][TestDoc]       | [![TestBadge]][Test] | None                                    |
| Universal Windows | [ReactiveUI][UniDoc]                | [![CoreBadge]][Core] | [ReactiveUI.Events][CoreEvents]         |
| WPF               | [ReactiveUI.WPF][WpfDoc]            | [![WpfBadge]][Wpf]   | [ReactiveUI.Events.WPF][WpfEvents]      |
| Windows Forms     | [ReactiveUI.WinForms][WinDoc]       | [![WinBadge]][Win]   | [ReactiveUI.Events.WinForms][WinEvents] |
| Xamarin.Forms     | [ReactiveUI.XamForms][XamDoc]       | [![XamBadge]][Xam]   | [ReactiveUI.Events.XamForms][XamEvents] |
| Xamarin.Essentials| [ReactiveUI][XamDoc]                | [![CoreBadge]][Core] | [ReactiveUI.Events.XamEssentials][XamE] |
| Xamarin.Android   | [ReactiveUI.AndroidSupport][DroDoc] | [![DroBadge]][Dro]   | [ReactiveUI.Events][CoreEvents]         |
| Xamarin.iOS       | [ReactiveUI][IosDoc]                | [![CoreBadge]][Core] | [ReactiveUI.Events][CoreEvents]         |
| Xamarin.Mac       | [ReactiveUI][MacDoc]                | [![CoreBadge]][Core] | [ReactiveUI.Events][CoreEvents]         |
| Tizen             | [ReactiveUI][CoreDoc]               | [![CoreBadge]][Core] | [ReactiveUI.Events][CoreEvents]         |
| Platform Uno      | ReactiveUI.Uno                      | [![UnoBadge]][Uno]  | None                                     |
| Avalonia          | [Avalonia.ReactiveUI][AvaDoc]       | [![AvaBadge]][Ava]   | None                                    |
| Any               | [ReactiveUI.Validation][ValidationsDocs]    | [![ValidationsBadge]][ValidationsCore] | None

[Core]: https://www.nuget.org/packages/ReactiveUI/
[CoreEvents]: https://www.nuget.org/packages/ReactiveUI.Events/
[CoreBadge]: https://img.shields.io/nuget/v/ReactiveUI.svg
[CoreDoc]: https://reactiveui.net/docs/getting-started/installation/

[Fody]: https://www.nuget.org/packages/ReactiveUI.Fody/
[FodyDoc]: https://reactiveui.net/docs/handbook/view-models/#managing-boilerplate-code
[FodyBadge]: https://img.shields.io/nuget/v/ReactiveUI.Fody.svg

[Test]: https://www.nuget.org/packages/ReactiveUI.Testing/
[TestBadge]: https://img.shields.io/nuget/v/ReactiveUI.Testing.svg
[TestDoc]: https://reactiveui.net/docs/handbook/testing/

[UniDoc]: https://reactiveui.net/docs/getting-started/installation/universal-windows-platform

[Wpf]: https://www.nuget.org/packages/ReactiveUI.WPF/
[WpfEvents]: https://www.nuget.org/packages/ReactiveUI.Events.WPF/
[WpfBadge]: https://img.shields.io/nuget/v/ReactiveUI.WPF.svg
[WpfDoc]: https://reactiveui.net/docs/getting-started/installation/windows-presentation-foundation

[Win]: https://www.nuget.org/packages/ReactiveUI.WinForms/
[WinEvents]: https://www.nuget.org/packages/ReactiveUI.Events.WinForms/
[WinBadge]: https://img.shields.io/nuget/v/ReactiveUI.WinForms.svg
[WinDoc]: https://reactiveui.net/docs/getting-started/installation/windows-forms

[Xam]: https://www.nuget.org/packages/ReactiveUI.XamForms/
[XamEvents]: https://www.nuget.org/packages/ReactiveUI.Events.XamForms/
[XamBadge]: https://img.shields.io/nuget/v/ReactiveUI.XamForms.svg
[XamDoc]: https://reactiveui.net/docs/getting-started/installation/xamarin-forms
[XamE]: https://www.nuget.org/packages/ReactiveUI.Events.XamEssentials/

[Dro]: https://www.nuget.org/packages/ReactiveUI.AndroidSupport/
[DroBadge]: https://img.shields.io/nuget/v/ReactiveUI.AndroidSupport.svg
[DroDoc]: https://reactiveui.net/docs/getting-started/installation/xamarin-android

[MacDoc]: https://reactiveui.net/docs/getting-started/installation/xamarin-mac
[IosDoc]: https://reactiveui.net/docs/getting-started/installation/xamarin-ios

[Uno]: https://www.nuget.org/packages/ReactiveUI.Uno/
[UnoBadge]: https://img.shields.io/nuget/v/ReactiveUI.Uno.svg
[UnoDoc]: https://reactiveui.net/docs/getting-started/installation/uno-platform


[Ava]: https://www.nuget.org/packages/Avalonia.ReactiveUI/
[AvaBadge]: https://img.shields.io/nuget/v/Avalonia.ReactiveUI.svg
[AvaDoc]: https://reactiveui.net/docs/getting-started/installation/avalonia
[EventsDocs]: https://reactiveui.net/docs/handbook/events/

[ValidationsCore]: https://www.nuget.org/packages/ReactiveUI.Validation/
[ValidationsBadge]: https://img.shields.io/nuget/v/ReactiveUI.Validation.svg
[ValidationsDocs]: https://reactiveui.net/docs/handbook/user-input-validation/

<h2>A Compelling Example</h2>

Let’s say you have a text field, and whenever the user types something into it, you want to make a network request which searches for that query.

![](http://i.giphy.com/xTka02wR2HiFOFACoE.gif)

```csharp
public interface ISearchViewModel
{
    string SearchQuery { get; set; }	 
    ReactiveCommand<string, IEnumerable<SearchResult>> Search { get; }
    IEnumerable<SearchResult> SearchResults { get; }
}
```

<h3>Define under what conditions a network request will be made</h3>

We're describing here, in a *declarative way*, the conditions in which the Search command is enabled. Now our Command IsEnabled is perfectly efficient, because we're only updating the UI in the scenario when it should change.

```csharp
var canSearch = this.WhenAnyValue(x => x.SearchQuery, query => !string.IsNullOrWhiteSpace(query));
```

<h3>Make the network connection</h3>

ReactiveCommand has built-in support for background operations and guarantees that this block will only run exactly once at a time, and that the CanExecute will auto-disable and that property IsExecuting will be set accordingly whilst it is running.

```csharp
Search = ReactiveCommand.CreateFromTask(_ => searchService.Search(this.SearchQuery), canSearch);
```

<h3>Update the user interface</h3>

ReactiveCommands are themselves `IObservables`, whose values are the results from the async method, guaranteed to arrive on the UI thread. We're going to take the list of search results that the background operation loaded, and turn them into our SearchResults property declared as [`ObservableAsPropertyHelper<T>`](https://reactiveui.net/docs/handbook/oaph/#example).

```csharp
_searchResults = Search.ToProperty(this, x => x.SearchResults);
```

<h3>Handling failures</h3>

Any exception thrown from the [`ReactiveCommand.CreateFromTask`](https://reactiveui.net/docs/handbook/commands/) gets piped to the `ThrownExceptions` Observable. Subscribing to this allows you to handle errors on the UI thread.

```csharp
Search.ThrownExceptions.Subscribe(error => { /* Handle exceptions. */ });
```

<h3>Throttling network requests and automatic search execution behaviour</h3>

Whenever the Search query changes, we're going to wait for one second of "dead airtime", then automatically invoke the subscribe command.

```csharp
this.WhenAnyValue(x => x.SearchQuery)
    .Throttle(TimeSpan.FromSeconds(1), RxApp.MainThreadScheduler)
    .InvokeCommand(Search);
```

<h3>Binding our ViewModel to the platform-specific UI</h3>

ReactiveUI fully supports XAML markup bindings, but we have more to offer. [ReactiveUI Bindings](https://reactiveui.net/docs/handbook/data-binding/) work on **all platforms**, including Xamarin Native and Windows Forms, and operate the same. Those bindings are strongly typed, and renaming a ViewModel property, or a control in the UI layout without updating the binding, the build will fail.

```csharp
this.WhenActivated(cleanup => 
{
    this.Bind(ViewModel, x => x.SearchQuery, x => x.TextBox)
        .DisposeWith(cleanup);
    this.OneWayBind(ViewModel, x => x.SearchResults, x => x.ListView)
        .DisposeWith(cleanup);
    this.BindCommand(ViewModel, x => x.Search, x => x.Button)
        .DisposeWith(cleanup);
});
```

<h3>Forget about INotifyPropertyChanged boilerplate code</h3>

[ReactiveUI.Fody](https://www.nuget.org/packages/ReactiveUI.Fody/) package allows you to decorate read-write properties with `Reactive` attribute — and code responsible for property change notifications will get injected into your property setters automatically at compile time. We use [Fody](https://github.com/Fody/Fody) tooling to make this magic work.

```csharp
public class ReactiveViewModel : ReactiveObject
{
    [Reactive] 
    public string SearchQuery { get; set; }
}
```

The code above gets compiled into the following code:

```csharp
public class ReactiveViewModel : ReactiveObject
{
    private string searchQuery;
    public string SearchQuery 
    {
        get => searchQuery;
        set => this.RaiseAndSetIfChanged(ref searchQuery, value);
    }
}
```

<h3>Validate user input on the fly</h3>

[ReactiveUI.Validation](https://github.com/reactiveui/ReactiveUI.Validation) provides a subset of functions to create validations, functioning in a reactive way. For those ViewModels which need validation, implement `ISupportsValidation`, then add validation rules to the ViewModel and finally bind to the validation rules in the View! See [documentation](https://reactiveui.net/docs/handbook/user-input-validation/) for more info. This package was created based on [jcmm33 work](https://github.com/jcmm33/ReactiveUI.Validation) and maintained by [alexmartinezm](https://github.com/alexmartinezm).

```csharp
// # ViewModel
// Search query must not be empty. The selector is the property 
// name and the line below is a single property validator.
this.ValidationRule(
    vm => vm.SearchQuery,
    query => !string.IsNullOrWhiteSpace(query),
    "Please, provide a non-empty search query!");

// # View
// Bind any validations which reference the SearchQuery property 
// to the text of the QueryValidation UI control!
this.BindValidation(ViewModel, vm => vm.SearchQuery, view => view.QueryValidation.Text);
```

<h3>Add view model-based routing to your XAML views</h3>

View model-based routing is supported for Xamarin.Forms, WinRT, UWP, Windows Forms, WPF and Avalonia Desktop applications. Create an [`IScreen`](https://reactiveui.net/api/reactiveui/iscreen/), register views for view models and navigate to your [`IRoutableViewModel`](https://reactiveui.net/api/reactiveui/iroutableviewmodel/)s by calling `Router.Navigate`. Then, bind the [`RoutingState`](https://reactiveui.net/api/reactiveui/routingstate/) to the platform-specific routed view host. See [routing documentation](https://reactiveui.net/docs/handbook/routing/) for a getting started guide.

```xml
<rxui:ReactiveWindow
    xmlns:rxui="http://reactiveui.net" 
    x:Class="ReactiveRouting.MainWindow"
    x:TypeArguments="vm:MainViewModel"
    xmlns:vm="clr-namespace:ReactiveRouting"
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
    <rxui:RoutedViewHost
        Router="{Binding Router}"
        HorizontalContentAlignment="Stretch"
        VerticalContentAlignment="Stretch" />
</rxui:ReactiveWindow>
```

<h2>Support</h2>

If you have a question, please see if any discussions in our [GitHub issues](https://github.com/reactiveui/ReactiveUI/issues) or [Stack Overflow](https://stackoverflow.com/questions/tagged/reactiveui) have already answered it.

If you want to discuss something or just need help, here is our [Slack room](https://reactiveui.net/slack) where there are always individuals looking to help out!

If you are twitter savvy you can tweet #reactiveui with your question and someone should be able to reach out and help also.

If you have discovered a 🐜 or have a feature suggestion, feel free to create an issue on GitHub.

<h2>Contribute</h2>

ReactiveUI is developed under an OSI-approved open source license, making it freely usable and distributable, even for commercial use. Because of our Open Collective model for funding and transparency, we are able to funnel support and funds through to our contributors and community. We ❤ the people who are involved in this project, and we’d love to have you on board, especially if you are just getting started or have never contributed to open-source before.

So here's to you, lovely person who wants to join us — this is how you can support us:

* [Responding to questions on StackOverflow](https://stackoverflow.com/questions/tagged/reactiveui)
* [Passing on knowledge and teaching the next generation of developers](http://ericsink.com/entries/dont_use_rxui.html)
* [Donations](https://reactiveui.net/donate) and [Corporate Sponsorships](https://reactiveui.net/sponsorship)
* [Submitting documentation updates where you see fit or lacking](https://reactiveui.net/docs)
* [Making contributions to the code base](https://reactiveui.net/contribute/)
* [Asking your employer to reciprocate and contribute to open-source](https://github.com/github/balanced-employee-ip-agreement)

We're also looking for people to assist with code reviews of ReactiveUI contributions. Please join us on <a href="https://reactiveui.net/slack">Slack</a> to discuss how.
<!--
 - [Android reviewers](https://github.com/orgs/reactiveui/teams/android-team)
 - [Apple TV reviewers](https://github.com/orgs/reactiveui/teams/tvos-team)
 - [Dot Net Core](https://github.com/orgs/reactiveui/teams/dotnetcore-team)
 - [Fody reviewers](https://github.com/orgs/reactiveui/teams/fody-team)
 - [iOS reviewers](https://github.com/orgs/reactiveui/teams/ios-team)
 - [Learning Team reviewers](https://github.com/orgs/reactiveui/teams/learning-team)
 - [Mac reviewers](https://github.com/orgs/reactiveui/teams/mac-team)
 - [ReactiveUI Core reviewers](https://github.com/orgs/reactiveui/teams/core-team)
 - [Tizen](https://github.com/orgs/reactiveui/teams/tizen-team)
 - [UWP reviewers](https://github.com/orgs/reactiveui/teams/uwp-team)
 - [Web Assembly](https://github.com/orgs/reactiveui/teams/webassembly-team)
 - [WinForms reviewers](https://github.com/orgs/reactiveui/teams/winforms-team)
 - [WPF reviewers](https://github.com/orgs/reactiveui/teams/wpf-team) 
 - [Xamarin Forms reviewers](https://github.com/orgs/reactiveui/teams/xamarin-forms-team)
 -->

<h2>.NET Foundation</h2>

ReactiveUI is part of the [.NET Foundation](https://www.dotnetfoundation.org/). Other projects that are associated with the foundation include the Microsoft .NET Compiler Platform ("Roslyn") as well as the Microsoft ASP.NET family of projects, Microsoft .NET Core & Xamarin Forms.

<h2>Core Team</h2>

<table>
  <tbody>
    <tr>
      <td align="center" valign="top">
        <img width="100" height="100" src="https://github.com/glennawatson.png?s=150">
        <br>
        <a href="https://github.com/glennawatson">Glenn Watson</a>
        <p>Melbourne, Australia</p>
      </td>
      <td align="center" valign="top">
        <img width="100" height="100" src="https://github.com/rlittlesii.png?s=150">
        <br>
        <a href="https://github.com/rlittlesii">Rodney Littles II</a>
        <p>Texas, USA</p>
      </td>
      <td align="center" valign="top">
        <img width="100" height="100" src="https://github.com/worldbeater.png?s=150">
        <br>
        <a href="https://github.com/worldbeater">Artyom Gorchakov</a>
        <p>Moscow, Russia</p>
      </td>
      <td align="center" valign="top">
        <img width="100" height="100" src="https://github.com/cabauman.png?s=150">
        <br>
        <a href="https://github.com/cabauman">Colt Bauman</a>
        <p>South Korea</p>
      </td>
    </tr>
  </tbody>
</table>

<h2>Alumni Core Team</h2>

The following have been core team members in the past.

<table>
  <tbody>
    <tr>
      <td align="center" valign="top">
        <img width="100" height="100" src="https://github.com/ghuntley.png?s=150">
        <br>
        <a href="https://github.com/ghuntley">Geoffrey Huntley</a>
        <p>Sydney, Australia</p>
      </td>
      <td align="center" valign="top">
        <img width="100" height="100" src="https://github.com/kentcb.png?s=150">
        <br>
        <a href="https://github.com/kentcb">Kent Boogaart</a>
        <p>Brisbane, Australia</p>
      </td>
      <td align="center" valign="top">
        <img width="100" height="100" src="https://github.com/olevett.png?s=150">
        <br>
        <a href="https://github.com/olevett">Olly Levett</a>
        <p>London, United Kingdom</p>
      </td>
      <td align="center" valign="top">
        <img width="100" height="100" src="https://github.com/anaisbetts.png?s=150">
        <br>
        <a href="https://github.com/anaisbetts">Anaïs Betts</a>
        <p>San Francisco, USA</p>
      </td>
      <td align="center" valign="top">
        <img width="100" height="100" src="https://github.com/shiftkey.png?s=150">
        <br>
        <a href="https://github.com/shiftkey">Brendan Forster</a>
        <p>Melbourne, Australia</p>
      </td>
      <td align="center" valign="top">
        <img width="120" height="100" src="https://github.com/onovotny.png?s=150">
        <br>
        <a href="https://github.com/onovotny">Oren Novotny</a>
        <p>New York, USA</p>
      </td>
     </tr>
  </tbody>
</table>

<h2>Contributors</h2>
This project exists thanks to all the people who have contributed to the code base.
<a href="https://github.com/ReactiveUI/ReactiveUI/graphs/contributors"><img src="https://opencollective.com/ReactiveUI/contributors.svg?width=890&button=false" /></a>

<h2>Sponsorship</h2>

The core team members, ReactiveUI contributors and contributors in the ecosystem do this open source work in their free time. If you use ReactiveUI a serious task, and you'd like us to invest more time on it, please donate. This project increases your income/productivity too. It makes development and applications faster and it reduces the required bandwidth.

This is how we use the donations:

* Allow the core team to work on ReactiveUI
* Thank contributors if they invested a large amount of time in contributing
* Support projects in the ecosystem that are of great value for users
* Support projects that are voted most (work in progress)
* Infrastructure cost
* Fees for money handling

<h2>Sponsors</h2>

[Become a sponsor](https://opencollective.com/reactiveui#sponsor) and get your logo on our README on Github with a link to your site.

<a href="https://opencollective.com/reactiveui#sponsor"><img src="https://opencollective.com/reactiveui/sponsor.svg?width=890&avatarHeight=50&button=false"></a>

<h2>Backers</h2>

[Become a backer](https://opencollective.com/reactiveui#backer) and get your image on our README on Github with a link to your site.

<a href="https://opencollective.com/reactiveui#backer"><img src="https://opencollective.com/reactiveui/backer.svg?width=890&avatarHeight=50&button=false"></a>
