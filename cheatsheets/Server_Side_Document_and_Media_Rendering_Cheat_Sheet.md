# Server-Side Document and Media Rendering Cheat Sheet

## Introduction

Many applications turn user-influenced content into another format on the server: HTML invoices into PDF, uploads into thumbnails, videos into previews, office documents into PDF. The engines that do this, such as wkhtmltopdf, headless Chromium, WeasyPrint, ImageMagick, Ghostscript, librsvg, FFmpeg and LibreOffice, are full interpreters for complex formats. Most of them can fetch URLs, read local files or hand the input to other programs, with the network access and file permissions of the server. Many are permissive out of the box: ImageMagick, for example, is [intentionally open by default](https://imagemagick.org/security-policy/) and expects you to restrict it.

The same few controls protect against all of them, so start there and treat the engine settings as a second layer. For accepting and storing the files in the first place, see the [File Upload Cheat Sheet](File_Upload_Cheat_Sheet.md). For SSRF in general, see the [Server-Side Request Forgery Prevention Cheat Sheet](Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md).

## Threats

- **SSRF to internal services and cloud metadata.** An `<iframe>`, `<img>`, CSS `url()` or playlist entry makes the engine request an internal address, and the response ends up in the output. [CVE-2022-35583](https://nvd.nist.gov/vuln/detail/CVE-2022-35583) is an SSRF in wkhtmltopdf through an injected `<iframe>`.
- **Local file read.** `file:` URLs, SVG `xi:include` and XML entities can pull server files into the output, as in [CVE-2023-38633](https://nvd.nist.gov/vuln/detail/CVE-2023-38633) in librsvg.
- **Code execution.** Some engines pass input to other programs or interpreters. ImageTragick ([CVE-2016-3714](https://nvd.nist.gov/vuln/detail/CVE-2016-3714)) ran shell commands through crafted images, and Ghostscript's PostScript sandbox has been bypassed repeatedly, for example in [CVE-2023-36664](https://nvd.nist.gov/vuln/detail/CVE-2023-36664).
- **Resource exhaustion.** Small inputs can declare huge dimensions, deep nesting or long media and keep a worker busy or out of memory. See the [Denial of Service Cheat Sheet](Denial_of_Service_Cheat_Sheet.md).

## Controls for Every Renderer

Engine settings reduce the attack surface, but most of the CVEs above bypassed a built-in restriction. Put the security boundary around the process:

- **No network, or an allowlist enforced by the network.** Deny outbound traffic by default and allow only the origins documents really need, such as your own asset host. Block private ranges, loopback and link-local `169.254.0.0/16`. Enforce it with a firewall, network policy or egress proxy rather than a URL check in the application, which [DNS rebinding](Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md#network-layer) can get around because the engine resolves the name again. On AWS, also require [IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-IMDS-existing-instances.html).
- **Block `file:` and other schemes.** Configure the engine to refuse `file:` and any scheme other than the ones the document needs, and don't open untrusted documents from a local path.
- **A throwaway sandbox per conversion.** Run each job in a fresh container or worker as a non-root user, with a read-only file system except a scratch directory and no credentials or secrets. Destroy it afterwards so one job can't see another's input or output.
- **Timeouts and resource limits.** Set a wall-clock timeout and CPU, memory, process and output size limits, and kill the whole process tree when one is hit. Limiting input size isn't enough, since even small documents can take a [very long time to render](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#security).
- **Escape user data before templating.** When the application builds HTML from user data, injected markup is how most HTML-to-PDF SSRF starts. Escape output as described in the [Cross Site Scripting Prevention Cheat Sheet](Cross_Site_Scripting_Prevention_Cheat_Sheet.md).
- **Accept only the formats you need** and tell the engine which format to expect, rather than letting it detect the format from the content. Many of these attacks rely on a file being parsed as a different format than the application checked.
- **Keep engines current, and replace unmaintained ones.** Their fixes are mostly for exactly this kind of input.

## Engine Notes

### wkhtmltopdf

The [repository](https://github.com/wkhtmltopdf/wkhtmltopdf) is archived, its engine is based on a QtWebKit that stopped getting updates years ago, and the [project status page](https://wkhtmltopdf.org/status.html) says not to use it with untrusted HTML, so plan a move to a maintained engine. It has no switch to turn networking off, so rely on network isolation. Local file access is blocked by default only since [0.12.6](https://github.com/wkhtmltopdf/wkhtmltopdf/releases/tag/0.12.6), so pass `--disable-local-file-access` on every version, and `--disable-javascript` when scripts aren't needed ([usage](https://wkhtmltopdf.org/usage/wkhtmltopdf.txt)).

### Headless Chromium (Puppeteer, Playwright)

Turn JavaScript off when the document doesn't need it, and use [request interception](https://pptr.dev/guides/network-interception) or [`page.route()`](https://playwright.dev/docs/network) to allow known origins and refuse `file:` as a second layer. Keep the Chromium sandbox on: don't launch with `--no-sandbox` for untrusted input ([Puppeteer troubleshooting](https://pptr.dev/troubleshooting)), and set Playwright's [`chromiumSandbox`](https://playwright.dev/docs/api/class-browsertype#browser-type-launch-option-chromium-sandbox) to `true`, since it is off by default. Use a new browser context per conversion.

### WeasyPrint

It runs no JavaScript, but by default it fetches every URL in the document, `file:` included ([access to local files](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#access-to-local-files)). Pass a custom [URL fetcher](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#url-fetchers) that allows the expected origins and refuses the rest.

### ImageMagick

The default policy allows every coder and delegate. Use a restrictive [security policy](https://imagemagick.org/security-policy/), starting from the shipped `websafe` or `secure` policy, that allows only the formats you accept, disables delegates and indirect reads, and sets resource limits. Name the expected format explicitly, such as `png:input`.

### Ghostscript

It interprets PostScript, a full programming language, and is often reached through ImageMagick. Never pass `-dNOSAFER`, but don't treat [`-dSAFER`](https://ghostscript.readthedocs.io/en/latest/Use.html#use-safer) as a boundary either, and don't accept PostScript or EPS from untrusted users unless you must.

### librsvg

It only loads [referenced files](https://gnome.pages.gitlab.gnome.org/librsvg/Rsvg-2.0/class.Handle.html#security-and-locations-of-referenced-files) from the base file's directory or below, and refuses everything but `data:` when loaded from memory without a base URL, which is the safest mode for untrusted SVG. Use 2.56.3 or later for the CVE-2023-38633 fix.

### FFmpeg

It detects the format from the content, so an upload named `video.mp4` can be a playlist or concat script that reads local files or internal URLs. Force the demuxer with `-f`, and restrict inputs with [`format_whitelist`](https://ffmpeg.org/ffmpeg-formats.html#Format-Options) and [`protocol_whitelist`](https://ffmpeg.org/ffmpeg-protocols.html#Protocol-Options), since all protocols are allowed by default.

### LibreOffice

Documents can link to external data and URLs, as in [CVE-2024-12426](https://nvd.nist.gov/vuln/detail/CVE-2024-12426), so run headless conversions with no outbound network. Use a fresh user profile per conversion with [`-env:UserInstallation`](https://help.libreoffice.org/latest/en-US/text/shared/guide/start_parameters.html) and follow the [security advisories](https://www.libreoffice.org/security/).

## References

- [ImageMagick Security Policy](https://imagemagick.org/security-policy/)
- [FFmpeg Protocols Documentation](https://ffmpeg.org/ffmpeg-protocols.html)
- [WeasyPrint documentation: Security](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#security)
