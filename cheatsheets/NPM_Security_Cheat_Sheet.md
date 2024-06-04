# NPM Security best practices

In the following npm cheatsheet, we’re going to focus on [10 npm security best practices](https://snyk.io/blog/ten-npm-security-best-practices) and productivity tips, useful for JavaScript and Node.js developers.

## 1) Avoid publishing secrets to the npm registry

Whether you’re making use of API keys, passwords or other secrets, they can very easily end up leaking into source control or even a published package on the public npm registry. You may have secrets in your working directory in designated files such as a `.env` which should be added to a `.gitignore` to avoid committing it to a SCM, but what happen when you publish an npm package from the project’s directory?

The npm CLI packs up a project into a tar archive (tarball) in order to push it to the registry. The following criteria determine which files and directories are added to the tarball:

- If there is either a `.gitignore` or a `.npmignore` file, the contents of the file are used as an ignore pattern when preparing the package for publication.
- If both ignore files exist, everything not located in `.npmignore` is published to the registry. This condition is a common source of confusion and is a problem that can lead to leaking secrets.

Developers may end up updating the `.gitignore` file, but forget to update `.npmignore` as well, which can lead to a potentially sensitive file not being pushed to source control, but still being included in the npm package.

Another good practice to adopt is making use of the `files` property in package.json, which works as an allowlist and specifies the array of files to be included in the package that is to be created and installed (while the ignore file functions as a denylist). The `files` property and an ignore file can both be used together to determine which files should explicitly be included, as well as excluded, from the package. When using both, the former the `files` property in package.json takes precedence over the ignore file.

When a package is published, the npm CLI will verbosely display the archive being created. To be extra careful, add a `--dry-run` command-line argument to your publish command in order to first review how the tarball is created without actually publishing it to the registry.

In January 2019, npm shared on their blog that they added a [mechanism that automatically revokes a token](https://blog.npmjs.org/post/182015409750/automated-token-revocation-for-when-you) if they detect that one has been published with a package.

## 2) Enforce the lockfile

We embraced the birth of package lockfiles with open arms, which introduced: deterministic installations across different environments, and enforced dependency expectations across team collaboration. Life is good! Or so I thought… what would have happened had I slipped a change into the project’s `package.json` file but had forgotten to commit the lockfile alongside of it?

Both Yarn, and npm act the same during dependency installation . When they detect an inconsistency between the project’s `package.json` and the lockfile, they compensate for such change based on the `package.json` manifest by installing different versions than those that were recorded in the lockfile.

This kind of situation can be hazardous for build and production environments as they could pull in unintended package versions and render the entire benefit of a lockfile futile.

Luckily, there is a way to tell both Yarn and npm to adhere to a specified set of dependencies and their versions by referencing them from the lockfile. Any inconsistency will abort the installation. The command-line should read as follows:

- If you’re using Yarn, run `yarn install --frozen-lockfile`.
- If you’re using npm run `npm ci`.

## 3) Minimize attack surfaces by ignoring run-scripts

The npm CLI works with package run-scripts. If you’ve ever run `npm start` or `npm test` then you’ve used package run-scripts too. The npm CLI builds on scripts that a package can declare, and allows packages to define scripts to run at specific entry points during the package’s installation in a project. For example, some of these [script hook](https://docs.npmjs.com/misc/scripts) entries may be `postinstall` scripts that a package that is being installed will execute in order to perform housekeeping chores.

With this capability, bad actors may create or alter packages to perform malicious acts by running any arbitrary command when their package is installed. A couple of cases where we’ve seen this already happening is the popular [eslint-scope incident](https://snyk.io/vuln/npm:eslint-scope:20180712) that harvested npm tokens, and the [crossenv incident](https://snyk.io/vuln/npm:crossenv:20170802), along with 36 other packages that abused a typosquatting attack on the npm registry.

Apply these npm security best practices in order to minimize the malicious module attack surface:

- Always vet and perform due-diligence on third-party modules that you install in order to confirm their health and credibility.
- Hold-off on upgrading immediately to new versions; allow new package versions some time to circulate before trying them out.
- Before upgrading, make sure to review changelog and release notes for the upgraded version.
- When installing packages make sure to add the `--ignore-scripts` suffix to disable the execution of any scripts by third-party packages.
- Consider adding `ignore-scripts` to your `.npmrc` project file, or to your global npm configuration.

## 4) Assess npm project health

### npm outdated command

Rushing to constantly upgrade dependencies to their latest releases is not necessarily a good practice if it is done without reviewing release notes, the code changes, and generally testing new upgrades in a comprehensive manner. With that said, staying out of date and not upgrading at all, or after a long time, is a source for trouble as well.

The npm CLI can provide information about the freshness of dependencies you use with regards to their semantic versioning offset. By running `npm outdated`, you can see which packages are out of date. Dependencies in yellow correspond to the semantic versioning as specified in the package.json manifest, and dependencies colored in red mean that there’s an update available. Furthermore, the output also shows the latest version for each dependency.

### npm doctor command

Between the variety of Node.js package managers, and different versions of Node.js you may have installed in your path, how do you verify a healthy npm installation and working environment? Whether you’re working with the npm CLI in a development environment or within a CI, it is important to assess that everything is working as expected.

Call the doctor! The npm CLI incorporates a health assessment tool to diagnose your environment for a well-working npm interaction. Run `npm doctor` to review your npm setup:

- Check the official npm registry is reachable, and display the currently configured registry.
- Check that Git is available.
- Review installed npm and Node.js versions.
- Run permission checks on the various folders such as the local and global `node_modules`, and on the folder used for package cache.
- Check the local npm module cache for checksum correctness.

## 5) Audit for vulnerabilities in open source dependencies

The npm ecosystem is the single largest repository of application libraries amongst all the other language ecosystems. The registry and the libraries in it are at the core for JavaScript developers as they are able to leverage work that others have already built and incorporate it into their codebase. With that said, the increasing adoption of open source libraries in applications brings with it an increased risk of introducing security vulnerabilities.

Many popular npm packages have been found to be vulnerable and may carry a significant risk without proper security auditing of your project’s dependencies. Some examples are npm [request](https://snyk.io/vuln/npm:request:20160119), [superagent](https://snyk.io/vuln/search?q=superagent&type=npm), [mongoose](https://snyk.io/vuln/search?q=mongoose&type=npm), and even security-related packages like [jsonwebtoken](https://snyk.io/vuln/npm:jsonwebtoken:20150331), and  [validator](https://snyk.io/vuln/search?q=validator&type=npm).

Security doesn’t end by just scanning for security vulnerabilities when installing a package but should also be streamlined with developer workflows to be effectively adopted throughout the entire lifecycle of software development, and monitored continuously when code is deployed:

- Scan for security vulnerabilities in [third-party open source projects](https://owasp.org/www-community/Component_Analysis)
- Monitor snapshots of your project's manifests so you can receive alerts when new CVEs impact them

## 6) Use a local npm proxy

The npm registry is the biggest collection of packages that is available for all JavaScript developers and is also the home of the most of the Open Source projects for web developers. But sometimes you might have different needs in terms of security, deployments or performance. When this is true, npm allows you to switch to a different registry:

When you run `npm install`, it automatically starts a communication with the main registry to resolve all your dependencies; if you wish to use a different registry, that too is pretty straightforward:

- Set `npm set registry` to set up a default registry.
- Use the argument `--registry` for one single registry.

[Verdaccio](https://verdaccio.org/) is a simple lightweight zero-config-required private registry and installing it is as simple as follows: `$ npm install --global verdaccio`.

Hosting your own registry was never so easy! Let’s check the most important features of this tool:

- It supports the npm registry format including private package features, scope support, package access control and authenticated users in the web interface.
- It provides capabilities to hook remote registries and the power to route each dependency to different registries and caching tarballs. To reduce duplicate downloads and save bandwidth in your local development and CI servers, you should proxy all dependencies.
- As an authentication provider by default, it uses an htpasswd security, but also supports Gitlab, Bitbucket, LDAP. You can also use your own.
- It’s easy to scale using a different storage provider.
- If your project is based in Docker, using the official image is the best choice.
- It enables really fast bootstrap for testing environments, and is handy for testing big mono-repos projects.

## 7) Responsibly disclose security vulnerabilities

When security vulnerabilities are found, they pose a potentially serious threat if they are publicised without prior warning or appropriate remedial action for users who cannot protect themselves.

It is recommended that security researchers follow a responsible disclosure program, which is a set of processes and guidelines that aims to connect the researchers with the vendor or maintainer of the vulnerable asset, in order to convey the vulnerability, it’s impact and applicability. Once the vulnerability is correctly triaged, the vendor and researcher coordinate a fix and a publication date for the vulnerability in an effort to provide an upgrade-path or remediation for affected users before the security issue is made public.

## 8) Enable 2FA

In October 2017, npm officially announced support for two-factor authentication (2FA) for developers using the npm registry to host their closed and open source packages.

Even though 2FA has been supported on the npm registry for a while now, it seems to be slowly adopted with one example being the eslint-scope incident in mid-2018 when a stolen developer account on the ESLint team lead to a [malicious version of eslint-scope](https://snyk.io/vuln/npm:eslint-scope) being published by bad actors.

Enabling 2FA is an easy and significant win for an npm security best practices. The registry supports two modes for enabling 2FA in a user’s account:

- Authorization-only—when a user logs in to npm via the website or the CLI, or performs other sets of actions such as changing profile information.
- Authorization and write-mode—profile and log-in actions, as well as write actions such as managing tokens and packages, and minor support for team and package visibility information.

Equip yourself with an authentication application, such as Google Authentication, which you can install on a mobile device, and you’re ready to get started. One easy way to get started with the 2FA extended protection for your account is through npm’s user interface, which allows enabling it very easily. If you’re a command-line person, it’s also easy to enable 2FA when using a supported npm client version (>=5.5.1):

```sh
npm profile enable-2fa auth-and-writes
```

Follow the command-line instructions to enable 2FA, and to save emergency authentication codes. If you wish to enable 2FA mode for login and profile changes only, you may replace the `auth-and-writes` with `auth-only` in the code as it appears above.

## 9) Use npm author tokens

Every time you log in with the npm CLI, a token is generated for your user and authenticates you to the npm registry. Tokens make it easy to perform npm registry-related actions during CI and automated procedures, such as accessing private modules on the registry or publishing new versions from a build step.

Tokens can be managed through the npm registry website, as well as using the npm command-line client. An example of using the CLI to create  a read-only token that is restricted to a specific IPv4 address range is as follows:

```sh
npm token create --read-only --cidr=192.0.2.0/24
```

To verify which tokens are created for your user or to revoke tokens in cases of emergency, you can use `npm token list` or `npm token revoke` respectively.

Ensure you are following this npm security best practice by protecting and minimizing the exposure of your npm tokens.

## 10) Understand module naming conventions and typosquatting attacks

Naming a module is the first thing you might do when creating a package, but before defining a final name, npm defines some rules that a package name must follow:

- It is limited to 214 characters
- It cannot start with dot or underscore
- No uppercase letters in the name
- No trailing spaces
- Only lowercase
- Some special characters are not allowed: “~\’!()*”)’
- Can’t start with . or _
- Can’t use node_modules or favicon.ico due are banned
- Even if you follow these rules, be aware that npm uses a spam detection mechanism when publishing new packages, based on score and whether a package name violates the terms of the service. If conditions are violated, the registry might deny the request.

Typosquatting is an attack that relies on mistakes made by users, such as typos. With typosquatting, bad actors could publish malicious modules to the npm registry with names that look much like existing popular modules.

We have been tracking tens of malicious packages in the npm ecosystem; they have been seen on the PyPi Python registry as well. Perhaps some of the most popular incidents have been for [cross-env](https://snyk.io/vuln/npm:crossenv:20170802), [event-stream](https://snyk.io/vuln/SNYK-JS-EVENTSTREAM-72638), and [eslint-scope](https://snyk.io/vuln/npm:eslint-scope:20180712).

One of the main targets for typosquatting attacks are the user credentials, since any package has access to environment variables via the global variable process.env. Other examples we’ve seen in the past include the case with event-stream, where the attack targeted developers in the hopes of [injecting malicious code](https://snyk.io/blog/a-post-mortem-of-the-malicious-event-stream-backdoor) into an application’s source code.

Closing our list of ten npm security best practices are the following tips to reduce the risk of such attacks:

- Be extra-careful when copy-pasting package installation instructions into the terminal. Make sure to verify in the source code repository as well as on the npm registry that this is indeed the package you are intending to install. You might verify the metadata of the package with `npm info` to fetch more information about contributors and latest versions.
- Default to having an npm logged-out user in your daily work routines so your credentials won’t be the weak spot that would lead to easily compromising your account.
- When installing packages, append the `--ignore-scripts` to reduce the risk of arbitrary command execution. For example: `npm install my-malicious-package --ignore-scripts`
