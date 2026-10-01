# Welcome to the OWASP Cheat Sheet Series

[![OWASP Flagship](https://img.shields.io/badge/owasp-flagship%20project-48A646.svg)](https://owasp.org/projects/cheat-sheet-series)
[![Creative Commons License](https://img.shields.io/github/license/OWASP/CheatSheetSeries)](https://creativecommons.org/licenses/by-sa/4.0/ "CC BY-SA 4.0")

Welcome to the official repository for the Open Worldwide Application Security Project® (OWASP) Cheat Sheet Series project. The project focuses on providing good security practices for builders in order to secure their applications.

In order to read the cheat sheets and **reference** them, use the project [official website](https://cheatsheetseries.owasp.org). The project details can be viewed on the [OWASP main website](https://owasp.org/projects/cheat-sheet-series) without the cheat sheets.

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
- [STARS](https://subtle-arrow-fonts-98.pages.dev/ja/stars/)
- [SYM 1D46C](https://chibi-heart-symbols-15.pages.dev/symbol/sym-1d46c/)
- [FREE FIRE CLAN EMPEROR CROWN](https://cyber-clan-tags-20.pages.dev/symbol/free-fire-clan-emperor-crown/)
- [SYM 262A](https://neon-futuristic-symbols-58.pages.dev/symbol/sym-262a/)
- [SYM 267F](https://lace-bow-kaomoji-80.pages.dev/symbol/sym-267f/)
- [SYM 26A3](https://gothic-bio-fonts-93.pages.dev/symbol/sym-26a3/)
- [SYM 1F47A](https://mystic-rune-text-88.pages.dev/symbol/sym-1f47a/)
- [SYM 1D433](https://vintage-bow-text-15.pages.dev/symbol/sym-1d433/)
- [QUARTER MUSICAL NOTE](https://pastel-chibi-kaomoji-14.pages.dev/symbol/quarter-musical-note/)
- [SYM 2614](https://coquette-bow-symbols-94.pages.dev/symbol/sym-2614/)
- [SYM 26C8](https://gothic-bio-fonts-70.pages.dev/symbol/sym-26c8/)
- [ZODIAC CELESTIAL](https://vintage-bow-text-15.pages.dev/vi/zodiac-celestial/)
- [SYM 26ED](https://otaku-symbol-vault-32.pages.dev/symbol/sym-26ed/)
- [SYM 1F929](https://mystic-rune-text-88.pages.dev/symbol/sym-1f929/)
- [SYM 263B](https://matrix-glitch-symbols-43.pages.dev/symbol/sym-263b/)
- [SYM 1D451](https://coquette-aesthetic-symbols-91.pages.dev/symbol/sym-1d451/)
- [SYM 1D40E](https://zen-dot-characters-20.pages.dev/symbol/sym-1d40e/)
- [SYM 1D416](https://soft-manga-emoticons-45.pages.dev/symbol/sym-1d416/)
- [TRENDING](https://mystic-rune-text-88.pages.dev/ru/trending/)
- [GAMING WEAPONS](https://mystic-rune-text-88.pages.dev/es/gaming-weapons/)
- [SYM 1D413](https://angelic-soft-text-23.pages.dev/symbol/sym-1d413/)
- [SYM 1F49E](https://angelic-soft-text-23.pages.dev/symbol/sym-1f49e/)
- [DISCORD STATUS](https://mystic-rune-text-88.pages.dev/vi/discord-status/)
- [TELUGU RIBBON BOWLET](https://synthwave-glitch-symbols-42.pages.dev/symbol/telugu-ribbon-bowlet/)
- [KAOMOJI](https://angelic-soft-text-23.pages.dev/es/kaomoji/)
- [SYM 2632](https://zen-dot-characters-20.pages.dev/symbol/sym-2632/)
- [RIGHT WING CLAN FLARE](https://sleek-mono-fonts-79.pages.dev/symbol/right-wing-clan-flare/)
- [SYM 1F618](https://neon-hacker-fonts-47.pages.dev/symbol/sym-1f618/)
- [SYM 26B0](https://pastel-chibi-kaomoji-14.pages.dev/symbol/sym-26b0/)
- [ARIES ZODIAC RAM](https://zen-dot-characters-20.pages.dev/symbol/aries-zodiac-ram/)
- [SYM 1D40A](https://pastel-chibi-kaomoji-14.pages.dev/symbol/sym-1d40a/)
- [SYM 26B8](https://pure-space-symbols-65.pages.dev/symbol/sym-26b8/)
- [CRYING TEARS SAD KAOMOJI](https://gothic-bio-fonts-70.pages.dev/symbol/crying-tears-sad-kaomoji/)
- [SYM 1FA75](https://minimal-star-symbols-17.pages.dev/symbol/sym-1fa75/)
- [SYM 26B3](https://angelic-soft-text-23.pages.dev/symbol/sym-26b3/)
- [SYM 2643](https://neon-hacker-fonts-47.pages.dev/symbol/sym-2643/)
- [LACE BOW KAOMOJI 80.PAGES.DEV](https://lace-bow-kaomoji-80.pages.dev/)
- [SYM 268A](https://neon-matrix-symbols-11.pages.dev/symbol/sym-268a/)
- [SYM 1D445](https://angelic-soft-fonts-31.pages.dev/symbol/sym-1d445/)
- [SYM 1F601](https://otaku-symbol-vault-32.pages.dev/symbol/sym-1f601/)
- [DAGGER BLADE](https://coquette-aesthetic-symbols-91.pages.dev/symbol/dagger-blade/)
- [RINGED PLANET SATURN](https://mystic-rune-text-88.pages.dev/symbol/ringed-planet-saturn/)
- [FREEFIRE NAMES](https://mystic-rune-text-88.pages.dev/es/freefire-names/)
- [SYM 26E8](https://baroque-fancy-text-80.pages.dev/symbol/sym-26e8/)
- [RIGHT BLACK LENTICULAR BRACKET](https://zen-dot-characters-20.pages.dev/symbol/right-black-lenticular-bracket/)
- [AESTHETIC STARDUST COMBO](https://matrix-unicode-symbols-12.pages.dev/symbol/aesthetic-stardust-combo/)
- [SYM 1D496](https://pastel-chibi-kaomoji-14.pages.dev/symbol/sym-1d496/)
- [SYM 1FAE5](https://matrix-unicode-symbols-12.pages.dev/symbol/sym-1fae5/)
- [SYM 1F4A9](https://anime-sparkle-text-97.pages.dev/symbol/sym-1f4a9/)
- [ZODIAC CELESTIAL](https://clean-line-fonts-70.pages.dev/vi/zodiac-celestial/)
- [FREEFIRE NAMES](https://otaku-symbol-vault-32.pages.dev/es/freefire-names/)
- [SYM 1D429](https://matrix-glitch-symbols-43.pages.dev/symbol/sym-1d429/)
- [SYM 1D472](https://pastel-chibi-kaomoji-14.pages.dev/symbol/sym-1d472/)
- [SYM 2678](https://angelic-soft-text-23.pages.dev/symbol/sym-2678/)
- [SYM 267A](https://pure-space-symbols-65.pages.dev/symbol/sym-267a/)
- [SYM 1F624](https://matrix-unicode-symbols-12.pages.dev/symbol/sym-1f624/)
- [TRENDING](https://pure-space-symbols-65.pages.dev/ja/trending/)
- [SYM 1D448](https://cyber-clan-tags-93.pages.dev/symbol/sym-1d448/)
- [SHADOWED WHITE STAR](https://mystic-rune-text-88.pages.dev/symbol/shadowed-white-star/)
- [SYM 1F631](https://zen-dot-characters-20.pages.dev/symbol/sym-1f631/)
- [ZODIAC CELESTIAL](https://mystic-rune-text-88.pages.dev/ja/zodiac-celestial/)
- [SYM 1F622](https://pure-space-symbols-65.pages.dev/symbol/sym-1f622/)
- [SYM 1D42A](https://pastel-chibi-kaomoji-14.pages.dev/symbol/sym-1d42a/)
- [ROBLOX NAMES](https://vintage-bow-text-15.pages.dev/vi/roblox-names/)
- [RADIOACTIVE SYMBOL](https://angelic-ribbon-text-18.pages.dev/symbol/radioactive-symbol/)
- [CUPID FEATHERY ARROW](https://soft-angel-symbols-36.pages.dev/symbol/cupid-feathery-arrow/)
- [SYM 1D44D](https://pastel-chibi-kaomoji-14.pages.dev/symbol/sym-1d44d/)
- [SYM 2621](https://mecha-terminal-text-63.pages.dev/symbol/sym-2621/)
- [SYM 1D4A5](https://clean-line-fonts-70.pages.dev/symbol/sym-1d4a5/)
- [SYM 1D419](https://angelic-ribbon-text-18.pages.dev/symbol/sym-1d419/)
- [SYM 1F479](https://pink-bow-fonts-91.pages.dev/symbol/sym-1f479/)
- [SYM 1F618](https://mystic-rune-text-88.pages.dev/symbol/sym-1f618/)
- [SYM 1D443](https://zen-dot-characters-20.pages.dev/symbol/sym-1d443/)
- [SYM 1F974](https://matrix-unicode-symbols-12.pages.dev/symbol/sym-1f974/)
- [SYM 26B6](https://minimal-star-symbols-17.pages.dev/symbol/sym-26b6/)
- [SYM 1F635](https://mystic-rune-text-88.pages.dev/symbol/sym-1f635/)
- [SYM 1F499](https://zen-dot-characters-20.pages.dev/symbol/sym-1f499/)
- [SYM 2764 FE0F 200D 1FA79](https://minimal-star-symbols-17.pages.dev/symbol/sym-2764-fe0f-200d-1fa79/)
- [SYM 26E6](https://cyber-clan-tags-93.pages.dev/symbol/sym-26e6/)
- [SYM 1F61F](https://mecha-terminal-text-63.pages.dev/symbol/sym-1f61f/)
- [ARIES ZODIAC RAM](https://neon-hacker-fonts-47.pages.dev/symbol/aries-zodiac-ram/)
- [BORDERS DIVIDERS](https://baroque-fancy-text-80.pages.dev/es/borders-dividers/)
- [SYM 1D46F](https://soft-manga-emoticons-45.pages.dev/symbol/sym-1d46f/)
- [SYM 1D431](https://neo-matrix-text-97.pages.dev/symbol/sym-1d431/)
- [BORDERS DIVIDERS](https://sleek-mono-fonts-79.pages.dev/ru/borders-dividers/)
- [SYM 26E7](https://cyber-clan-tags-93.pages.dev/symbol/sym-26e7/)
- [STARS](https://minimal-star-symbols-51.pages.dev/stars/)
- [BLACK STAR](https://zen-dot-symbols-91.pages.dev/symbol/black-star/)
- [SYM 1D420](https://angelic-soft-fonts-31.pages.dev/symbol/sym-1d420/)
- [SYM 1D463](https://anime-sparkle-text-97.pages.dev/symbol/sym-1d463/)
- [SYM 1F640](https://zen-dot-characters-20.pages.dev/symbol/sym-1f640/)
- [SYM 262D](https://cyber-clan-tags-93.pages.dev/symbol/sym-262d/)
- [SYM 1FAE4](https://zen-dot-characters-20.pages.dev/symbol/sym-1fae4/)
- [SYM 1D478](https://chibi-emoticon-fonts-99.pages.dev/symbol/sym-1d478/)
- [SYM 1D457](https://mech-crosshair-symbols-83.pages.dev/symbol/sym-1d457/)
- [NEON MATRIX SYMBOLS 11.PAGES.DEV](https://neon-matrix-symbols-11.pages.dev/)
- [SYM 2634](https://mecha-terminal-text-63.pages.dev/symbol/sym-2634/)
- [BLACK FLORETTE FLOWER](https://angelic-ribbon-text-18.pages.dev/symbol/black-florette-flower/)
- [KAOMOJI](https://mecha-tech-text-62.pages.dev/kaomoji/)
- [ARROWS LINES](https://mystic-rune-text-88.pages.dev/ja/arrows-lines/)
- [SYM 1D409](https://zen-arrow-text-26.pages.dev/symbol/sym-1d409/)
- [PT](https://neon-hacker-fonts-72.pages.dev/pt/)
- [SYM 1D464](https://angelic-soft-fonts-31.pages.dev/symbol/sym-1d464/)
- [TRENDING](https://otaku-symbol-vault-32.pages.dev/ru/trending/)
- [SYM 1D469](https://mystic-rune-text-88.pages.dev/symbol/sym-1d469/)
- [STARS](https://modern-line-symbols-23.pages.dev/vi/stars/)
- [SKULL AND CROSSBONES](https://gothic-bio-fonts-70.pages.dev/symbol/skull-and-crossbones/)
- [SYM 26F9](https://pastel-chibi-kaomoji-14.pages.dev/symbol/sym-26f9/)
- [FREEFIRE NAMES](https://clean-line-fonts-70.pages.dev/freefire-names/)
- [SYM 26CA](https://matrix-glitch-symbols-43.pages.dev/symbol/sym-26ca/)
- [TIKTOK CAPTIONS](https://gothic-bio-fonts-70.pages.dev/vi/tiktok-captions/)
- [SYM 26D6](https://balletcore-bio-symbols-12.pages.dev/symbol/sym-26d6/)
- [GEORGIAN LOVE HEART](https://otaku-symbol-vault-32.pages.dev/symbol/georgian-love-heart/)
- [SYM 26BF](https://angelic-soft-fonts-31.pages.dev/symbol/sym-26bf/)
- [TWELVE POINTED STAR](https://vintage-bow-text-15.pages.dev/symbol/twelve-pointed-star/)
- [SYM 2731](https://neon-matrix-symbols-11.pages.dev/symbol/sym-2731/)
- [SYM 1D463](https://vintage-lace-text-34.pages.dev/symbol/sym-1d463/)
- [SYM 1F929](https://vintage-lace-text-34.pages.dev/symbol/sym-1f929/)
- [SYM 265E](https://occult-rune-symbols-48.pages.dev/symbol/sym-265e/)
- [WATER BUBBLES](https://moe-star-kaomoji-82.pages.dev/symbol/water-bubbles/)
- [SYM 1F604](https://soft-girl-aesthetic-fonts-19.pages.dev/symbol/sym-1f604/)
- [SYM 1D446](https://soft-pastel-bio-39.pages.dev/symbol/sym-1d446/)
- [PINWHEEL STAR](https://subtle-grid-text-34.pages.dev/symbol/pinwheel-star/)
- [RIGHT MATHEMATICAL WHITE SQUARE BRACKET](https://chibi-emoticon-vault-12.pages.dev/symbol/right-mathematical-white-square-bracket/)
- [SYM 1D40B](https://vintage-library-text-70.pages.dev/symbol/sym-1d40b/)
- [SYM 1F60F](https://modern-line-symbols-23.pages.dev/symbol/sym-1f60f/)
- [SYM 1D49F](https://neon-hacker-fonts-72.pages.dev/symbol/sym-1d49f/)
- [SYM 1D418](https://angelic-soft-fonts-31.pages.dev/symbol/sym-1d418/)
- [SYM 2639 FE0F](https://matrix-unicode-symbols-12.pages.dev/symbol/sym-2639-fe0f/)
- [DISCORD STATUS](https://moe-emoticon-library-79.pages.dev/pt/discord-status/)
