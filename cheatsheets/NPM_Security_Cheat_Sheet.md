# NPM Security best practices

The following cheatsheet covers several npm security best practices and productivity tips, useful for JavaScript and Node.js developers. This list was originally based on the [10 npm security best practices](https://snyk.io/blog/ten-npm-security-best-practices) from the Snyk blog.

## 1) Avoid publishing secrets to the npm registry

Whether you’re making use of API keys, passwords or other secrets, they can very easily end up leaking into source control or even a published package on the public npm registry. You may have secrets in your working directory in designated files such as a `.env` which should be added to a `.gitignore` to avoid committing it to a SCM, but what happens when you publish an npm package from the project’s directory?

The npm CLI packs up a project into a tar archive (tarball) in order to push it to the registry. The following criteria determine which files and directories are added to the tarball:

- If there is either a `.gitignore` or a `.npmignore` file, the contents of the file are used as an ignore pattern when preparing the package for publication.
- If both ignore files exist, everything not located in `.npmignore` is published to the registry. This condition is a common source of confusion and is a problem that can lead to leaking secrets.

Developers may end up updating the `.gitignore` file, but forget to update `.npmignore` as well, which can lead to a potentially sensitive file not being pushed to source control, but still being included in the npm package.

Another good practice to adopt is making use of the `files` property in package.json, which works as an allowlist and specifies the array of files to be included in the package that is to be created and installed (while the ignore file functions as a denylist). The `files` property and an ignore file can both be used together to determine which files should explicitly be included, as well as excluded, from the package. When using both, the former the `files` property in package.json takes precedence over the ignore file.

When a package is published, the npm CLI will verbosely display the archive being created. To be extra careful, add a `--dry-run` command-line argument to your publish command in order to first review how the tarball is created without actually publishing it to the registry.

For details about revoking access token, see the official documentation: [Revoking access tokens](https://docs.npmjs.com/revoking-access-tokens).

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

### Using an allowlist for lifecycle scripts

Disabling lifecycle scripts by default by adding `ignore-script` to your `.npmrc` file is the safest option. If you use packages that rely on lifecycle scripts for legitimate reasons, you can use a plugin like [`@lavamoat/allow-scripts`](https://github.com/LavaMoat/LavaMoat/tree/main/packages/allow-scripts) to create an _allowlist_ of packages authorized to run lifecylce scripts.

Here's how the allowlist would look like in the `package.json` file on a project using the popular image processing package [sharp](https://www.npmjs.com/package/sharp):

```json
{
  "lavamoat": {
    "allowScripts": {
      "sharp": true
    }
  }
}
```

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

Many popular npm packages have been found to be vulnerable and may carry a significant risk without proper security auditing of your project’s dependencies. Some examples are npm [request](https://snyk.io/vuln/npm:request:20160119), [superagent](https://snyk.io/vuln/search?q=superagent&type=npm), [mongoose](https://snyk.io/vuln/search?q=mongoose&type=npm), and even security-related packages like [jsonwebtoken](https://snyk.io/vuln/npm:jsonwebtoken:20150331), and [validator](https://snyk.io/vuln/search?q=validator&type=npm).

Security doesn’t end by just scanning for security vulnerabilities when installing a package but should also be streamlined with developer workflows to be effectively adopted throughout the entire lifecycle of software development, and monitored continuously when code is deployed:

- Scan for security vulnerabilities in [third-party open source projects](https://owasp.org/www-community/Component_Analysis)
- Monitor snapshots of your project's manifests so you can receive alerts when new CVEs impact them [OWASP Dependency-Track](https://owasp.org/www-project-dependency-track/)

## 6) Artifact governance and supply chain protections

### Use a local npm proxy

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

### Governance & Verification Steps

Supply-chain attacks increasingly target build artifacts, registries and CI credentials. Add lightweight governance and verification steps to reduce risk and improve response time:

- Track provenance and produce an SBOM for builds (CycloneDX/SPDX) so you can trace what was built and where inputs originated.

  CycloneDX Example:

  ```bash
  # Generate SBOM
  npm install @cyclonedx/cyclonedx-npm
  npx @cyclonedx/cyclonedx-npm --validate > sbom.json # Use the flag `--omit dev` to exclude dev dependencies from SBOM if needed
  ```

- Sign artifacts and build provenance (for example, use Sigstore / cosign or similar signing tools) so consumers can verify integrity before installing.

  Sigstore Example:

  ```javascript
  // sign-and-verify.js
  // npm install sigstore fs

  import * as fs from 'fs';
  import * as sigstore from 'sigstore';

  // Path to your built npm package (via `npm pack`)
  const artifact = 'my-lib-1.0.0.tgz';

  // --- Sign ---
  const payload = fs.readFileSync(artifact);
  const bundle = await sigstore.sign(payload);
  fs.writeFileSync(`${artifact}.sigstore.json`, JSON.stringify(bundle, null, 2));
  console.log('Signed:', artifact);

  // --- Verify ---
  await sigstore.verify(payload, bundle);
  console.log('Verified OK!');
  ```

- Prefer immutable, access-controlled registries or vetted mirrors (private registries, Verdaccio with an upstream cache, or [approved mirrors](#use-a-local-npm-proxy)) and enable retention / immutability policies where available.
- Restrict, scope and rotate CI and publisher tokens. Bind publisher tokens to workflows or IP ranges and minimize privileges.
- Verify packages during CI: check signatures or provenance, validate the SBOM, [run SCA and static analysis](#5-audit-for-vulnerabilities-in-open-source-dependencies), and [install from pinned lockfile resolutions](#2-enforce-the-lockfile).
- Automate monitoring and alerts for unusual publishes, token usage or dependency changes and keep a documented remediation playbook (revoke tokens, deprecate/yank compromised packages, publish fixes and notify consumers).

These measures are incremental and low-risk to adopt. Combined they make supply-chain attacks harder and speed up identification & recovery if a compromise occurs.

## 7) Responsibly disclose security vulnerabilities

When security vulnerabilities are found, they pose a potentially serious threat if they are publicised without prior warning or appropriate remedial action for users who cannot protect themselves.

It is recommended that security researchers follow a responsible disclosure program, which is a set of processes and guidelines that aims to connect the researchers with the vendor or maintainer of the vulnerable asset, in order to convey the vulnerability, it’s impact and applicability. Once the vulnerability is correctly triaged, the vendor and researcher coordinate a fix and a publication date for the vulnerability in an effort to provide an upgrade-path or remediation for affected users before the security issue is made public.

## 8) Enable 2FA

Enabling two-factor authentication (2FA) is a critical npm security best practice. The npm registry supports two modes for enabling 2FA in a user’s account:

- Authorization-only—when a user logs in to npm via the website or the CLI, or performs other sets of actions such as changing profile information.
- Authorization and write-mode—profile and log-in actions, as well as write actions such as managing tokens and packages, and minor support for team and package visibility information.

To get started, see the official documentation: [Requiring 2FA](https://docs.npmjs.com/requiring-2fa-for-package-publishing-and-settings-modification).

Equip yourself with an authentication application, such as Google Authentication, which you can install on a mobile device, and you’re ready to get started. One easy way to get started with the 2FA extended protection for your account is through npm’s user interface, which allows enabling it very easily. If you’re a command-line person, it’s also easy to enable 2FA when using a supported npm client version (>=5.5.1):

```sh
npm profile enable-2fa auth-and-writes
```

Follow the command-line instructions to enable 2FA, and to save emergency authentication codes. If you wish to enable 2FA mode for login and profile changes only, you may replace the `auth-and-writes` with `auth-only` in the code as it appears above.

## Additional Security Resources

- [About secret scanning](https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning)
- [Best practices for securing accounts](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure)

## 9) Use npm author tokens

Every time you log in with the npm CLI, a token is generated for your user and authenticates you to the npm registry. Tokens make it easy to perform npm registry-related actions during CI and automated procedures, such as accessing private modules on the registry or publishing new versions from a build step.

Tokens can be managed through the npm registry website, as well as using the npm command-line client. An example of using the CLI to create a read-only token that is restricted to a specific IPv4 address range is as follows:

```sh
npm token create --read-only --cidr=192.0.2.0/24
```

To verify which tokens are created for your user or to revoke tokens in cases of emergency, you can use `npm token list` or `npm token revoke` respectively.

Ensure you are following this npm security best practice by protecting and minimizing the exposure of your npm tokens.

## 10) Understanding typosquatting and slopsquatting attacks

### Typosquatting attacks

Typosquatting is an attack that relies on mistakes made by users, such as typos. With typosquatting, bad actors publish malicious modules to the npm registry with names that look much like existing popular modules. These malicious packages exploit common typing errors or visual similarities to trick developers into installing them instead of the legitimate packages they intended to use.

The Snyk security team has tracked tens of malicious packages in the npm ecosystem that used typosquatting to trick users into installing them; similar attacks have been observed on the PyPi Python registry as well. Some of the most notable incidents include [cross-env](https://snyk.io/vuln/npm:crossenv:20170802), [event-stream](https://snyk.io/vuln/SNYK-JS-EVENTSTREAM-72638), and [eslint-scope](https://snyk.io/vuln/npm:eslint-scope:20180712).

One of the main targets for typosquatting attacks are user credentials, since any package has access to environment variables via the global variable `process.env`. Other examples include the event-stream case, where attackers targeted developers in the hopes of [injecting malicious code](https://snyk.io/blog/a-post-mortem-of-the-malicious-event-stream-backdoor) into an application's source code.

### Slopsquatting attacks

Slopsquatting is a newer attack vector that exploits AI-powered coding assistants and Large Language Models (LLMs). When developers use AI tools to generate code or package recommendations, these models may occasionally "hallucinate" package names that don't actually exist. Attackers monitor these hallucinations and create malicious packages with those exact names, knowing that developers may blindly trust and install packages suggested by their AI assistants.

To protect against slopsquatting:

- Always verify that packages suggested by AI tools actually exist and are legitimate
- Check the package's repository, download statistics, and maintainer information
- Cross-reference AI suggestions with official documentation
- Be skeptical of packages with very low download counts or recent creation dates
- Review the package source code before installing, especially for AI-suggested packages

## 11) Use trusted publishers for secure package publishing

Traditional npm publishing relies on long-lived tokens that can be compromised or accidentally exposed. Trusted publishing with OpenID Connect (OIDC) provides a more secure alternative by using short-lived, workflow-specific credentials that are automatically generated during CI/CD processes. Trusted publishing currently supports GitHub Actions and GitLab CI/CD Pipelines.

### How trusted publishing works

Trusted publishing creates a trust relationship between npm and your CI/CD provider using OIDC. When you configure a trusted publisher for your package, npm will accept publishes from the specific workflow you've authorized, in addition to traditional authentication methods like npm tokens and manual publishes. The npm CLI automatically detects OIDC environments and uses them for authentication before falling back to traditional tokens.

This approach eliminates the security risks associated with long-lived write tokens, which can be compromised, accidentally exposed in logs, or require manual rotation. Instead, each publish uses short-lived, cryptographically-signed tokens that are specific to your workflow and cannot be extracted or reused.

### Automatic provenance generation

When publishing via trusted publishing, npm automatically generates provenance attestations that provide cryptographic proof of package authenticity. This helps users verify that packages come from legitimate sources and haven't been tampered with.

For more information, see the [npm trusted publishing documentation](https://docs.npmjs.com/trusted-publishers).

## Final Recommendations

Closing our list of npm security best practices are the following tips to reduce the risk of such attacks:

- Be extra-careful when copy-pasting package installation instructions into the terminal. Make sure to verify in the source code repository as well as on the npm registry that this is indeed the package you are intending to install. You might verify the metadata of the package with `npm info` to fetch more information about contributors and latest versions.
- Default to having an npm logged-out user in your daily work routines so your credentials won’t be the weak spot that would lead to easily compromising your account.
- When installing packages, append the `--ignore-scripts` to reduce the risk of arbitrary command execution. For example: `npm install my-malicious-package --ignore-scripts`
