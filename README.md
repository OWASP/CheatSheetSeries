# Welcome to the OWASP Cheat Sheet Series

[![OWASP Flagship](https://img.shields.io/badge/owasp-flagship%20project-48A646.svg)](https://www.owasp.org/index.php/OWASP_Project_Inventory#tab=Flagship_Projects)
[![Creative Commons License](https://img.shields.io/github/license/OWASP/CheatSheetSeries)](https://creativecommons.org/licenses/by-sa/4.0/ "CC BY-SA 4.0")

Welcome to the official repository for the Open Worldwide Application Security Project® (OWASP) Cheat Sheet Series project. The project focuses on providing good security practices for builders in order to secure their applications.

In order to read the cheat sheets and **reference** them, use the project [official website](https://cheatsheetseries.owasp.org). The project details can be viewed on the [OWASP main website](https://owasp.org/www-project-cheat-sheets/) without the cheat sheets.

:triangular_flag_on_post: Markdown files are the working sources and aren't intended to be referenced in any external documentation, books or websites.

## Cheat Sheet Series Team

### Project Leaders

- [Jim Manico](https://github.com/jmanico)
- [Jakub Maćkowski](https://github.com/mackowski)
- [Gabriel Corona](https://github.com/randomstuff)

### Core team

- [Kevin W. Wall](https://github.com/kwwall)
- [Shlomo Zalman Heigh](https://github.com/szh)

## Chat With Us

We're easy to find on Slack:

1. Join the OWASP Group Slack with this [invitation link](https://owasp.org/slack/invite).
2. Join the [#cheatsheets channel](https://owasp.slack.com/messages/C073YNUQG).

Feel free to ask questions, suggest ideas, or share your best recipes.

## Contributions, Feature Requests, and Feedback

We are actively inviting new contributors! To start, please read the [contribution guide](CONTRIBUTING.md) and our [How To Make A Cheatsheet guide](GUIDELINE.md).

This project is only possible thanks to the work of many dedicated volunteers. Everyone is encouraged to help in ways large and small. Here are a few ways you can help:

- Read the current content and help us fix any spelling mistakes or grammatical errors.
- Choose an existing [issue](https://github.com/OWASP/CheatSheetSeries/issues) on GitHub and submit a pull request to fix it.
- Open a new issue to report an opportunity for improvement.

### Automated Build

This [link](https://cheatsheetseries.owasp.org/bundle.zip) allows you to download a build (ZIP archive) of the offline website.

### Local Build [![pyVersion3x](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/downloads/)

The OWASP Cheat Sheet Series website can be built and tested locally by issuing the following commands:

```sh
make install-python-requirements
make generate-site
make serve  # Binds port 8000
```

### Linting

To check markdown and terminology:

```sh
npm run lint-markdown
npm run lint-terminology
```

To auto-fix linting issues:

```sh
npm run lint-markdown-fix
npm run lint-terminology-fix
```

### Container Build

The OWASP Cheat Sheet Series website can be built and tested locally inside a container by issuing the following commands:

#### Docker

```sh
docker build -t cheatsheetseries .
docker run --name cheatsheetseries -p 8000:8000 cheatsheetseries
```

#### Podman

```sh
podman build -t cheatsheetseries .
podman run --name cheatsheetseries -p 8000:8000 localhost/cheatsheetseries
```

## Contributors

- **From 2014 to 2018:** [V1](CONTRIBUTOR-V1.md) - Initial version of the project hosted on the [OWASP WIKI](https://wiki.owasp.org).
- **From 2019:** [V2](https://github.com/OWASP/CheatSheetSeries/graphs/contributors) - Hosted on [GitHub](https://github.com/OWASP/CheatSheetSeries).

## Special thanks

A special thank you to the following people for their help provided during the migration:

- [Dominique Righetto](https://github.com/righettod): For his special leadership and guidance.
- [Elie Saad](https://github.com/ThunderSon): For valuable help in updating the OWASP Wiki links for all the migrated cheat sheets and for years of leadership and other project support.
- [Jakub Maćkowski](https://github.com/mackowski): For valuable help in updating the OWASP Wiki links for all the migrated cheat sheets.

Open Worldwide Application Security Project and OWASP are registered trademarks of the OWASP Foundation, Inc.


## 🌐 Web Resources & Aesthetic Symbols Index
- [BORDERS DIVIDERS](https://lace-heart-kaomoji-64.pages.dev/ja/borders-dividers/)
- [BEAMED SIXTEENTH MUSICAL NOTES](https://cyber-clan-tags-23.pages.dev/symbol/beamed-sixteenth-musical-notes/)
- [SYM 1F644](https://ribbon-heart-fonts-86.pages.dev/symbol/sym-1f644/)
- [SYM 26B0](https://sleek-line-symbols-51.pages.dev/symbol/sym-26b0/)
- [SYM 1D40F](https://coquette-aesthetic-symbols-86.pages.dev/symbol/sym-1d40f/)
- [BORDERS DIVIDERS](https://gothic-bio-fonts-13.pages.dev/borders-dividers/)
- [SYM 1F975](https://gothic-bio-fonts-13.pages.dev/symbol/sym-1f975/)
- [GAMING WEAPONS](https://soft-bow-fonts-22.pages.dev/es/gaming-weapons/)
- [SYM 1D497](https://scholarly-vintage-symbols-48.pages.dev/symbol/sym-1d497/)
- [GEMINI ZODIAC TWINS](https://occult-aesthetic-symbols-26.pages.dev/symbol/gemini-zodiac-twins/)
- [LEFT MATHEMATICAL WHITE SQUARE BRACKET](https://scholarly-vintage-symbols-48.pages.dev/symbol/left-mathematical-white-square-bracket/)
- [SYM 1D442](https://clean-aesthetic-fonts-73.pages.dev/symbol/sym-1d442/)
- [SYM 267E](https://sleek-bio-symbols-51.pages.dev/symbol/sym-267e/)
- [SYM 1D40E](https://clean-aesthetic-fonts-73.pages.dev/symbol/sym-1d40e/)
- [SYM 26FA](https://clean-aesthetic-fonts-73.pages.dev/symbol/sym-26fa/)
- [SYM 1F601](https://monochrome-text-lab-86.pages.dev/symbol/sym-1f601/)
- [SYM 260D](https://scholarly-vintage-symbols-48.pages.dev/symbol/sym-260d/)
- [BLACK FOUR POINT STAR](https://minimal-star-symbols-25.pages.dev/symbol/black-four-point-star/)
- [KAOMOJI](https://clean-aesthetic-fonts-73.pages.dev/es/kaomoji/)
- [SYM 2742](https://gothic-bio-fonts-86.pages.dev/symbol/sym-2742/)
- [SYM 1D440](https://clean-aesthetic-fonts-73.pages.dev/symbol/sym-1d440/)
- [SYM 1F649](https://monochrome-text-lab-86.pages.dev/symbol/sym-1f649/)
- [SYM 1D432](https://clean-aesthetic-fonts-73.pages.dev/symbol/sym-1d432/)
- [STARS](https://monochrome-text-lab-86.pages.dev/es/stars/)
- [SYM 2637](https://scholarly-vintage-symbols-48.pages.dev/symbol/sym-2637/)
- [GAMING WEAPONS](https://clean-aesthetic-fonts-73.pages.dev/ru/gaming-weapons/)
- [SYM 1F610](https://sleek-bio-symbols-51.pages.dev/symbol/sym-1f610/)
- [HEARTS](https://gothic-bio-fonts-86.pages.dev/pt/hearts/)
- [SYM 1F605](https://sleek-bio-symbols-51.pages.dev/symbol/sym-1f605/)
- [INSTAGRAM BIO](https://gothic-bio-fonts-86.pages.dev/vi/instagram-bio/)
- [SYM 26E3](https://clean-aesthetic-fonts-73.pages.dev/symbol/sym-26e3/)
- [SYM 1F915](https://scholarly-vintage-symbols-48.pages.dev/symbol/sym-1f915/)
- [TIKTOK CAPTIONS](https://clean-aesthetic-fonts-73.pages.dev/es/tiktok-captions/)
- [RADIOACTIVE SYMBOL](https://gothic-bio-fonts-86.pages.dev/symbol/radioactive-symbol/)
- [VIRGO ZODIAC MAIDEN](https://scholarly-vintage-symbols-48.pages.dev/symbol/virgo-zodiac-maiden/)
- [SYM 2655](https://scholarly-vintage-symbols-48.pages.dev/symbol/sym-2655/)
- [SYM 1F92E](https://monochrome-text-lab-86.pages.dev/symbol/sym-1f92e/)
- [SYM 1FAE1](https://sleek-bio-symbols-51.pages.dev/symbol/sym-1fae1/)
- [SYM 2627](https://minimal-star-symbols-25.pages.dev/symbol/sym-2627/)
- [SYM 2670](https://sleek-bio-symbols-51.pages.dev/symbol/sym-2670/)
- [AQUARIUS ZODIAC WATER BEARER](https://scholarly-vintage-symbols-48.pages.dev/symbol/aquarius-zodiac-water-bearer/)
- [PINWHEEL STAR](https://monochrome-text-lab-86.pages.dev/symbol/pinwheel-star/)
- [SYM 2630](https://angelic-bow-symbols-42.pages.dev/symbol/sym-2630/)
- [SYM 2747](https://neon-glitch-symbols-84.pages.dev/symbol/sym-2747/)
- [FOUR POINT STAR SPARKLE](https://clean-aesthetic-fonts-73.pages.dev/symbol/four-point-star-sparkle/)
- [SYM 1D46F](https://monochrome-text-lab-86.pages.dev/symbol/sym-1d46f/)
- [SYM 267D](https://minimal-star-symbols-25.pages.dev/symbol/sym-267d/)
- [GAMING WEAPONS](https://clean-aesthetic-fonts-73.pages.dev/pt/gaming-weapons/)
- [SYM 1F929](https://coquette-symbols.pages.dev/symbol/sym-1f929/)
- [SYM 1FAE8](https://theeduplaycampen.pages.dev/symbol/sym-1fae8/)
- [SYM 2671](https://scholarly-vintage-symbols-48.pages.dev/symbol/sym-2671/)
- [TRENDING](https://clean-aesthetic-fonts-73.pages.dev/ru/trending/)
- [MUSIC WEATHER](https://pastel-chibi-emotes-23.pages.dev/pt/music-weather/)
- [SYM 2683](https://clean-aesthetic-fonts-73.pages.dev/symbol/sym-2683/)
- [TIBETAN LOTUS BLOSSOM](https://matrix-hacker-text-52.pages.dev/symbol/tibetan-lotus-blossom/)
- [SYM 260A](https://coquette-symbols.pages.dev/symbol/sym-260a/)
- [SYM 1D44E](https://scholarly-cross-symbols-35.pages.dev/symbol/sym-1d44e/)
- [RINGED PLANET SATURN](https://scholarly-vintage-symbols-48.pages.dev/symbol/ringed-planet-saturn/)
- [SYM 26EF](https://vintage-library-rune-80.pages.dev/symbol/sym-26ef/)
- [SYM 1D452](https://clean-aesthetic-fonts-73.pages.dev/symbol/sym-1d452/)
- [AESTHETIC MINIMAL CLOUD](https://scholarly-vintage-symbols-48.pages.dev/symbol/aesthetic-minimal-cloud/)
- [SYM 1D43F](https://clean-aesthetic-fonts-73.pages.dev/symbol/sym-1d43f/)
- [SYM 1D400](https://neon-glitch-symbols-84.pages.dev/symbol/sym-1d400/)
- [SYM 1D42B](https://anime-sparkle-text-22.pages.dev/symbol/sym-1d42b/)
- [SYM 26D4](https://clean-aesthetic-fonts-73.pages.dev/symbol/sym-26d4/)
- [SYM 1F60A](https://scholarly-vintage-symbols-48.pages.dev/symbol/sym-1f60a/)
- [SYM 1F61F](https://theeduplaycampen.pages.dev/symbol/sym-1f61f/)
- [SYM 1D486](https://coquette-symbols.pages.dev/symbol/sym-1d486/)
- [SYM 1F63D](https://coquette-symbols.pages.dev/symbol/sym-1f63d/)
- [SYM 2639](https://scholarly-vintage-symbols-48.pages.dev/symbol/sym-2639/)
- [SYM 2744](https://vintage-library-rune-80.pages.dev/symbol/sym-2744/)
- [SYM 1D42B](https://clean-aesthetic-fonts-73.pages.dev/symbol/sym-1d42b/)
- [SYM 2672](https://sleek-bio-symbols-51.pages.dev/symbol/sym-2672/)
- [SYM 1F633](https://sleek-bio-symbols-51.pages.dev/symbol/sym-1f633/)
- [SYM 1D46E](https://ribbon-heart-fonts-86.pages.dev/symbol/sym-1d46e/)
- [SYM 1D447](https://minimal-star-symbols-93.pages.dev/symbol/sym-1d447/)
- [SYM 1F620](https://vintage-angel-symbols-66.pages.dev/symbol/sym-1f620/)
- [SYM 1F61B](https://monochrome-text-lab-86.pages.dev/symbol/sym-1f61b/)
- [SYM 2666](https://monochrome-text-lab-86.pages.dev/symbol/sym-2666/)
- [OPEN CENTRE STAR](https://vintage-library-rune-80.pages.dev/symbol/open-centre-star/)
- [SYM 1D4A4](https://neon-glitch-symbols-84.pages.dev/symbol/sym-1d4a4/)
- [SHADOWED WHITE STAR](https://neon-glitch-symbols-84.pages.dev/symbol/shadowed-white-star/)
- [RIGHT WING CLAN FLARE](https://minimal-star-symbols-25.pages.dev/symbol/right-wing-clan-flare/)
- [SYM 1D460](https://vintage-angel-symbols-66.pages.dev/symbol/sym-1d460/)
- [SYM 1F92C](https://ribbon-heart-fonts-86.pages.dev/symbol/sym-1f92c/)
- [SYM 1D47D](https://scholarly-cross-symbols-35.pages.dev/symbol/sym-1d47d/)
- [ROBLOX NAMES](https://dolly-kaomoji-text-94.pages.dev/es/roblox-names/)
- [MUSIC WEATHER](https://minimal-star-symbols-25.pages.dev/es/music-weather/)
- [SYM 1F649](https://minimal-star-symbols-25.pages.dev/symbol/sym-1f649/)
- [SYM 1F978](https://ribbon-heart-fonts-86.pages.dev/symbol/sym-1f978/)
- [SYM 2741](https://minimal-star-symbols-25.pages.dev/symbol/sym-2741/)
- [SYM 2734](https://theeduplaycampen.pages.dev/symbol/sym-2734/)
- [SYM 1F642 200D 2194 FE0F](https://minimal-star-symbols-25.pages.dev/symbol/sym-1f642-200d-2194-fe0f/)
- [SYM 1D49F](https://sleek-bio-symbols-51.pages.dev/symbol/sym-1d49f/)
- [SYM 26A2](https://scholarly-vintage-symbols-48.pages.dev/symbol/sym-26a2/)
- [SYM 1D40F](https://mecha-blade-symbols-46.pages.dev/symbol/sym-1d40f/)
- [LEFT RIGHT EXCHANGE ARROWS](https://vintage-library-rune-80.pages.dev/symbol/left-right-exchange-arrows/)
- [SYM 2638](https://scholarly-vintage-symbols-48.pages.dev/symbol/sym-2638/)
- [SINGLE EIGHTH MUSICAL NOTE](https://minimal-star-symbols-25.pages.dev/symbol/single-eighth-musical-note/)
- [SYM 1F92C](https://pastel-chibi-emotes-23.pages.dev/symbol/sym-1f92c/)
- [SYM 1D44B](https://theeduplaycampen.pages.dev/symbol/sym-1d44b/)
- [CANCER ZODIAC CRAB](https://scholarly-vintage-symbols-48.pages.dev/symbol/cancer-zodiac-crab/)
- [ZODIAC CELESTIAL](https://clean-aesthetic-fonts-73.pages.dev/ru/zodiac-celestial/)
- [SYM 2637](https://gothic-bio-fonts-13.pages.dev/symbol/sym-2637/)
- [SYM 1F929](https://coquette-aesthetic-symbols-86.pages.dev/symbol/sym-1f929/)
- [LEFT WING CLAN FLARE](https://scholarly-vintage-symbols-48.pages.dev/symbol/left-wing-clan-flare/)
- [RIGHTWARDS PAIRED HARPOON](https://coquette-aesthetic-symbols-86.pages.dev/symbol/rightwards-paired-harpoon/)
- [SYM 2639 FE0F](https://ribbon-heart-fonts-86.pages.dev/symbol/sym-2639-fe0f/)
- [SYM 1F611](https://kawaii-kaomoji-hub-96.pages.dev/symbol/sym-1f611/)
- [SYM 1D432](https://minimal-star-symbols-93.pages.dev/symbol/sym-1d432/)
- [SYM 1D44C](https://scholarly-cross-symbols-35.pages.dev/symbol/sym-1d44c/)
- [TAURUS ZODIAC BULL](https://scholarly-vintage-symbols-48.pages.dev/symbol/taurus-zodiac-bull/)
- [SYM 1F498](https://theeduplaycampen.pages.dev/symbol/sym-1f498/)
- [SYM 2684](https://mecha-blade-symbols-46.pages.dev/symbol/sym-2684/)
- [SYM 260F](https://scholarly-vintage-symbols-48.pages.dev/symbol/sym-260f/)
- [SYM 1D49A](https://coquette-symbols.pages.dev/symbol/sym-1d49a/)
- [TIBETAN LOTUS BLOSSOM](https://gothic-bio-fonts-86.pages.dev/symbol/tibetan-lotus-blossom/)
- [SYM 1F636](https://minimal-star-symbols-25.pages.dev/symbol/sym-1f636/)
- [SYM 1F601](https://scholarly-vintage-symbols-48.pages.dev/symbol/sym-1f601/)
- [SYM 26A7](https://minimal-star-symbols-93.pages.dev/symbol/sym-26a7/)
- [SYM 1F614](https://ribbon-heart-fonts-86.pages.dev/symbol/sym-1f614/)
- [SYM 1D469](https://vintage-angel-symbols-66.pages.dev/symbol/sym-1d469/)
- [SYM 1F611](https://ribbon-heart-fonts-86.pages.dev/symbol/sym-1f611/)
- [SYM 1F498](https://coquette-symbols.pages.dev/symbol/sym-1f498/)
- [SYM 2634](https://clean-dot-aesthetic-48.pages.dev/symbol/sym-2634/)
- [SYM 1F635 200D 1F4AB](https://sleek-bio-symbols-51.pages.dev/symbol/sym-1f635-200d-1f4ab/)
- [STAR OPERATOR](https://clean-aesthetic-fonts-73.pages.dev/symbol/star-operator/)
- [SYM 2746](https://monochrome-text-lab-86.pages.dev/symbol/sym-2746/)
- [SYM 26E2](https://monochrome-text-lab-86.pages.dev/symbol/sym-26e2/)
- [SYM 26A5](https://neon-glitch-symbols-84.pages.dev/symbol/sym-26a5/)
