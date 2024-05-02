# Node.js Docker Cheat Sheet

The following cheatsheet provides production-grade guidelines for building optimized and [secure Node.js Docker](https://snyk.io/blog/10-best-practices-to-containerize-nodejs-web-applications-with-docker/). You’ll find it helpful regardless of the Node.js application you aim to build. This article will be helpful for you if:

- your aim is to build a frontend application using server-side rendering (SSR) Node.js capabilities for React.
- you’re looking for advice on how to properly build a Node.js Docker image for your microservices, running Fastify, NestJS or other application frameworks.

## 1) Use explicit and deterministic Docker base image tags

It may seem to be an obvious choice to build your image based on the `node` Docker image, but what are you actually pulling in when you build the image? Docker images are always referenced by tags, and when you don’t specify a tag the default, `:latest` tag is used.

So, in fact, by specifying the following in your Dockerfile, you always build the latest version of the Docker image that has been built by the **Node.js Docker working group**:

### FROM node

The shortcomings of building based on the default `node` image are as follows:

1. Docker image builds are inconsistent. Just like we’re using `lockfiles` to get a deterministic `npm install` behavior every time we install npm packages, we’d also like to get deterministic docker image builds. If we build the image from node—which effectively means the `node:latest` tag—then every build will pull a newly built Docker image of `node`. We don’t want to introduce this sort of non-deterministic behavior.
2. The node Docker image is based on a full-fledged operating system, full of libraries and tools that you may or may not need to run your Node.js web application. This has two downsides. Firstly a bigger image means a bigger download size which, besides increasing the storage requirement, means more time to download and re-build the image. Secondly, it means you’re potentially introducing security vulnerabilities, that may exist in all of these libraries and tools, into the image.

In fact, the `node` Docker image is quite big and includes hundreds of security vulnerabilities of different types and severities. If you’re using it, then by default your starting point is going to be a baseline of 642 security vulnerabilities, and hundreds of megabytes of image data that is downloaded on every pull and build.

The recommendations for building better Docker images are:

1. Use small Docker images—this will translate to a smaller software footprint on the Docker image reducing the potential vulnerability vectors, and a smaller size, which will speed up the image build process
2. Use the Docker image digest, which is the static SHA256 hash of the image. This ensures that you are getting deterministic Docker image builds from the base image.

Based on this, let’s ensure that we use the Long Term Support (LTS) version of Node.js, and the minimal `alpine` image type to have the smallest size and software footprint on the image:

### FROM node:lts-alpine

Nonetheless, this base image directive will still pull new builds of that tag. We can find the `SHA256` hash for it in the [Docker Hub for this Node.js tag](https://hub.docker.com/layers/node/library/node/lts-alpine/images/sha256-51e341881c2b77e52778921c685e711a186a71b8c6f62ff2edfc6b6950225a2f?context=explore), or by running the following command once we pulled this image locally, and locate the `Digest` field in the output:

    $ docker pull node:lts-alpine
    lts-alpine: Pulling from library/node
    0a6724ff3fcd: Already exists
    9383f33fa9f3: Already exists
    b6ae88d676fe: Already exists
    565e01e00588: Already exists
    Digest: sha256:b2da3316acdc2bec442190a1fe10dc094e7ba4121d029cb32075ff59bb27390a
    Status: Downloaded newer image for node:lts-alpine
    docker.io/library/node:lts-alpine

Another way to find the `SHA256` hash is by running the following command:

    $ docker images --digests
    REPOSITORY                     TAG              DIGEST                                                                    IMAGE ID       CREATED             SIZE
    node                           lts-alpine       sha256:b2da3316acdc2bec442190a1fe10dc094e7ba4121d029cb32075ff59bb27390a   51d926a5599d   2 weeks ago         116MB

Now we can update the Dockerfile for this Node.js Docker image as follows:

    FROM node@sha256:b2da3316acdc2bec442190a1fe10dc094e7ba4121d029cb32075ff59bb27390a
    WORKDIR /usr/src/app
    COPY . /usr/src/app
    RUN npm install
    CMD "npm" "start"

However, the Dockerfile above, only specifies the Node.js Docker image name without an image tag which creates ambiguity for which exact image tag is being used—it’s not readable, hard to maintain and doesn’t create a good developer experience.

Let’s fix it by updating the Dockerfile, providing the full base image tag for the Node.js version that corresponds to that `SHA256` hash:

    FROM node:lts-alpine@sha256:b2da3316acdc2bec442190a1fe10dc094e7ba4121d029cb32075ff59bb27390a
    WORKDIR /usr/src/app
    COPY . /usr/src/app
    RUN npm install
    CMD "npm" "start"

## 2) Install only production dependencies in the Node.js Docker image

The following Dockerfile directive installs all dependencies in the container, including `devDependencies`, which aren’t needed for a functional application to work. It adds an unneeded security risk from packages used as development dependencies, as well as inflating the image size unnecessarily.

**`RUN npm install`**

Enforce deterministic builds with `npm ci`. This prevents surprises in a continuous integration (CI) flow because it halts if any deviations from the lockfile are made.

In the case of building a Docker image for production we want to ensure that we only install production dependencies in a deterministic way, and this brings us to the following recommendation for the best practice for installing npm dependencies in a container image:

**`RUN npm ci --omit=dev`**

The updated Dockerfile contents in this stage are as follows:

    FROM node:lts-alpine@sha256:b2da3316acdc2bec442190a1fe10dc094e7ba4121d029cb32075ff59bb27390a
    WORKDIR /usr/src/app
    COPY . /usr/src/app
    RUN npm ci --omit=dev
    CMD "npm" "start"

## 3) Optimize Node.js tooling for production

When you build your Node.js Docker image for production, you want to ensure that all frameworks and libraries are using the optimal settings for performance and security.

This brings us to add the following Dockerfile directive:

**`ENV NODE_ENV production`**

At first glance, this looks redundant, since we already specified only production dependencies in the `npm install` phase—so why is this necessary?

Developers mostly associate the `NODE_ENV=production` environment variable setting with the installation of production-related dependencies, however, this setting also has other effects which we need to be aware of.

Some frameworks and libraries may only turn on the optimized configuration that is suited to production if that `NODE_ENV` environment variable is set to `production`. Putting aside our opinion on whether this is a good or bad practice for frameworks to take, it is important to know this.

As an example, the [Express documentation](https://expressjs.com/en/advanced/best-practice-performance.html#set-node_env-to-production) outlines the importance of setting this environment variable for enabling performance and security related optimizations:

![Express documentation screenshot](https://lh3.googleusercontent.com/idNDKUUyML-rRpnNYmOo4eNBimq-u343401spkAdKWWKjNt0c_xux2Aw1W2r64qWGEcvxfQRkosPcO339g5DzQk0snm1nr6MupSPNB_zAtGgLsr3lp1L-tia4KgHwvOXMW1jT0J-)

The performance impact of the `NODE_ENV` variable could be very significant.

Many of the other libraries that you are relying on may also expect this variable to be set, so we should set this in our Dockerfile.

The updated Dockerfile should now read as follows with the `NODE_ENV` environment variable setting baked in:

    FROM node:lts-alpine@sha256:b2da3316acdc2bec442190a1fe10dc094e7ba4121d029cb32075ff59bb27390a
    ENV NODE_ENV production
    WORKDIR /usr/src/app
    COPY . /usr/src/app
    RUN npm ci --omit=dev
    CMD "npm" "start"

## 4) Don’t run containers as root

The principle of least privilege is a long-time security control from the early days of Unix and we should always follow this when we’re running our containerized Node.js web applications.

The threat assessment is pretty straight-forward—if an attacker is able to compromise the web application in a way that allows for [command injection](https://owasp.org/www-community/attacks/Command_Injection) or [directory path traversal](https://owasp.org/www-community/attacks/Path_Traversal), then these will be invoked with the user who owns the application process. If that process happens to be root then they can do virtually everything within the container, including [attempting a container escape or [privilege escalation](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation). Why would we want to risk it? You’re right, we don’t.

Repeat after me: **“friends don’t let friends run containers as root!”**

The official `node` Docker image, as well as its variants like `alpine`, include a least-privileged user of the same name: `node`. However, it’s not enough to just run the process as `node`. For example, the following might not be ideal for an application to function well:

    USER node
    CMD "npm" "start"

The reason for that is the `USER` Dockerfile directive only ensures that the process is owned by the `node` user. What about all the files we copied earlier with the `COPY` instruction? They are owned by root. That’s how Docker works by default.

The complete and proper way of dropping privileges is as follows, also showing our up to date Dockerfile practices up to this point:

    FROM node:lts-alpine@sha256:b2da3316acdc2bec442190a1fe10dc094e7ba4121d029cb32075ff59bb27390a
    ENV NODE_ENV production
    WORKDIR /usr/src/app
    COPY --chown=node:node . /usr/src/app
    RUN npm ci --omit=dev
    USER node
    CMD "npm" "start"

## 5) Properly handle events to safely terminate a Node.js Docker web application

One of the most common mistakes I see with blogs and articles about containerizing Node.js applications when running in Docker containers is the way that they invoke the process. All of the following and their variants are bad patterns you should avoid:

- `CMD “npm” “start”`
- `CMD [“yarn”, “start”]`
- `CMD “node” “server.js”`
- `CMD “start-app.sh”`

Let’s dig in! I’ll walk you through the differences between them and why they’re all patterns to avoid.

The following concerns are key to understanding the context for properly running and terminating Node.js Docker applications:

1. An orchestration engine, such as Docker Swarm, Kubernetes, or even just Docker engine itself, needs a way to send signals to the process in the container. Mostly, these are signals to terminate an application, such as `SIGTERM` and `SIGKILL`.
2. The process may run indirectly, and if that happens then it’s not always guaranteed that it will receive these signals.
3. The Linux kernel treats processes that run as process ID 1 (PID) differently than any other process ID.

Equipped with that knowledge, let’s begin investigating the ways of invoking the process for a container, starting off with the example from the Dockerfile we’re building:

**`CMD "npm" "start"`**

The caveat here is two fold. Firstly, we’re indirectly running the node application by directly invoking the npm client. Who’s to say that the npm CLI forwards all events to the node runtime? It actually doesn’t, and we can easily test that.

Make sure that in your Node.js application you set an event handler for the `SIGHUP` signal which logs to the console every time you’re sending an event. A simple code example should look as follows:

    function handle(signal) {
       console.log(`*^!@4=> Received event: ${signal}`)
    }
    process.on('SIGHUP', handle)

Then run the container, and once it’s up specifically send it the `SIGHUP` signal using the `docker` CLI and the special `--signal` command-line flag:

**`$ docker kill --signal=SIGHUP elastic_archimedes`**

Nothing happened, right? That’s because the npm client doesn’t forward any signals to the node process that it spawned.

The other caveat has to do with the different ways in which way you can specify the `CMD` directive in the Dockerfile. There are two ways, and they are not the same:

1. the shellform notation, in which the container spawns a shell interpreter that wraps the process. In such cases, the shell may not properly forward signals to your process.
2. the execform notation, which directly spawns a process without wrapping it in a shell. It is specified using the JSON array notation, such as: `CMD [“npm”, “start”]`. Any signals sent to the container are directly sent to the process.

Based on that knowledge, we want to improve our Dockerfile process execution directive as follows:

**`CMD ["node", "server.js"]`**

We are now invoking the node process directly, ensuring that it receives all of the signals sent to it, without it being wrapped in a shell interpreter.

However, this introduces another pitfall.

When processes run as PID 1 they effectively take on some of the responsibilities of an init system, which is typically responsible for initializing an operating system and processes. The kernel treats PID 1 in a different way than it treats other process identifiers. This special treatment from the kernel means that the handling of a `SIGTERM` signal to a running process won’t invoke a default fallback behavior of killing the process if the process doesn’t already set a handler for it.

To [quote the Node.js Docker working group recommendation](https://github.com/nodejs/docker-node/blob/master/docs/BestPractices.md#handling-kernel-signals) on this:  “Node.js was not designed to run as PID 1 which leads to unexpected behaviour when running inside of Docker. For example, a Node.js process running as PID 1 will not respond to SIGINT (CTRL-C) and similar signals”.

The way to go about it then is to use a tool that will act like an init process, in that it is invoked with PID 1, then spawns our Node.js application as another process whilst ensuring that all signals are proxied to that Node.js process. If possible, we’d like a small as possible tooling footprint for doing so to not risk having security vulnerabilities added to our container image.

One such tool is [dumb-init](https://engineeringblog.yelp.com/2016/01/dumb-init-an-init-for-docker.html) which is statically linked and has a small footprint. Here’s how we’ll set it up:

    RUN apk add dumb-init
    CMD ["dumb-init", "node", "server.js"]

This brings us to the following up to date Dockerfile. You’ll notice that we placed the `dumb-init` package install right after the image declaration, so we can take advantage of Docker’s caching of layers:

    FROM node:lts-alpine@sha256:b2da3316acdc2bec442190a1fe10dc094e7ba4121d029cb32075ff59bb27390a
    RUN apk add dumb-init
    ENV NODE_ENV production
    WORKDIR /usr/src/app
    COPY --chown=node:node . .
    RUN npm ci --omit=dev
    USER node
    CMD ["dumb-init", "node", "server.js"]

Good to know: `docker kill` and `docker stop` commands only send signals to the container process with PID 1. If you’re running a shell script that runs your Node.js application, then take note that a shell instance—such as `/bin/sh`, for example—doesn’t forward signals to child processes, which means your app will never get a `SIGTERM`.

## 6) Graceful tear down for your Node.js web applications

If we’re already discussing process signals that terminate applications, let’s make sure we’re shutting them down properly and gracefully without disrupting users.

When a Node.js application receives an interrupt signal, also known as `SIGINT`, or `CTRL+C`, it will cause an abrupt process kill, unless any event handlers were set of course to handle it in a different behavior. This means that connected clients to a web application will be immediately disconnected. Now, imagine hundreds of Node.js web containers orchestrated by Kubernetes, going up and down as needs arise to scale or manage errors. Not the greatest user experience.

You can easily simulate this problem. Here’s a stock Fastify web application example, with an inherent delayed response of 60 seconds for an endpoint:

    fastify.get('/delayed', async (request, reply) => {
     const SECONDS_DELAY = 60000
     await new Promise(resolve => {
         setTimeout(() => resolve(), SECONDS_DELAY)
     })
     return { hello: 'delayed world' }
    })
     
    const start = async () => {
     try {
       await fastify.listen(PORT, HOST)
       console.log(`*^!@4=> Process id: ${process.pid}`)
     } catch (err) {
       fastify.log.error(err)
       process.exit(1)
     }
    }
     
    start()

Run this application and once it’s running send a simple HTTP request to this endpoint:

`$ time curl https://localhost:3000/delayed`

Hit `CTRL+C` in the running Node.js console window and you’ll see that the curl request exited abruptly. This simulates the same experience your users would receive when containers tear down.

To provide a better experience, we can do the following:

1. Set an event handler for the various termination signals like `SIGINT` and `SIGTERM`.
2. The handler waits for clean up operations like database connections, ongoing HTTP requests and others.
3. The handler then terminates the Node.js process.

Specifically with Fastify, we can have our handler call on [fastify.close()](https://www.fastify.io/docs/latest/Server/) which returns a promise that we will await, and Fastify will also take care to respond to every new connection with the HTTP status code 503 to signal that the application is unavailable.

Let’s add our event handler:

    async function closeGracefully(signal) {
       console.log(`*^!@4=> Received signal to terminate: ${signal}`)
     
       await fastify.close()
       // await db.close() if we have a db connection in this app
       // await other things we should cleanup nicely
       process.exit()
    }
    process.on('SIGINT', closeGracefully)
    process.on('SIGTERM', closeGracefully)

Admittedly, this is more of a generic web application concern than Dockerfile related, but is even more important in orchestrated environments.

## 7) Find and fix security vulnerabilities in your Node.js docker image

See [Docker Security Cheat Sheet - Use static analysis tools](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-9-use-static-analysis-tools)

## 8) Use multi-stage builds

Multi-stage builds are a great way to move from a simple, yet potentially erroneous Dockerfile, into separated steps of building a Docker image, so we can avoid leaking sensitive information. Not only that, but we can also use a bigger Docker base image to install our dependencies, compile any native npm packages if needed, and then copy all these artifacts into a small production base image, like our alpine example.

### Prevent sensitive information leak

The use-case here to avoid sensitive information leakage is more common than you think.

If you’re building Docker images for work, there’s a high chance that you also maintain private npm packages. If that’s the case, then you probably needed to find some way to make that secret `NPM_TOKEN` available to the npm install.

Here’s an example for what I’m talking about:

    FROM node:lts-alpine@sha256:b2da3316acdc2bec442190a1fe10dc094e7ba4121d029cb32075ff59bb27390a
    RUN apk add dumb-init
    ENV NODE_ENV production
    ENV NPM_TOKEN 1234
    WORKDIR /usr/src/app
    COPY --chown=node:node . .
    #RUN npm ci --omit=dev
    RUN echo "//registry.npmjs.org/:_authToken=$NPM_TOKEN" > .npmrc && \
       npm ci --omit=dev
    USER node
    CMD ["dumb-init", "node", "server.js"]

Doing this, however, leaves the `.npmrc` file with the secret npm token inside the Docker image. You could attempt to improve it by deleting it afterwards, like this:

    RUN echo "//registry.npmjs.org/:_authToken=$NPM_TOKEN" > .npmrc && \
       npm ci --omit=dev
    RUN rm -rf .npmrc

However, now the `.npmrc` file is available in a different layer of the Docker image. If this Docker image is public, or someone is able to access it somehow, then your token is compromised. A better improvement would be as follows:

    RUN echo "//registry.npmjs.org/:_authToken=$NPM_TOKEN" > .npmrc && \
       npm ci --omit=dev; \
       rm -rf .npmrc

The problem now is that the Dockerfile itself needs to be treated as a secret asset, because it contains the secret npm token inside it.

Luckily, Docker supports a way to pass arguments into the build process:

    ARG NPM_TOKEN
    RUN echo "//registry.npmjs.org/:_authToken=$NPM_TOKEN" > .npmrc && \
       npm ci --omit=dev; \
       rm -rf .npmrc

And then we build it as follows:

**`$ docker build . -t nodejs-tutorial --build-arg NPM_TOKEN=1234`**

I know you were thinking that we’re all done at this point but, sorry to disappoint 🙂

That’s how it is with security—sometimes the obvious things are yet just another pitfall.

What’s the problem now, you ponder? Build arguments passed like that to Docker are kept in the history log. Let’s see with our own eyes. Run this command:

**`$ docker history nodejs-tutorial`**

which prints the following:

    IMAGE          CREATED              CREATED BY                                      SIZE      COMMENT
    b4c2c78acaba   About a minute ago   CMD ["dumb-init" "node" "server.js"]            0B        buildkit.dockerfile.v0
    <missing>      About a minute ago   USER node                                       0B        buildkit.dockerfile.v0
    <missing>      About a minute ago   RUN |1 NPM_TOKEN=1234 /bin/sh -c echo "//reg…   5.71MB    buildkit.dockerfile.v0
    <missing>      About a minute ago   ARG NPM_TOKEN                                   0B        buildkit.dockerfile.v0
    <missing>      About a minute ago   COPY . . # buildkit                             15.3kB    buildkit.dockerfile.v0
    <missing>      About a minute ago   WORKDIR /usr/src/app                            0B        buildkit.dockerfile.v0
    <missing>      About a minute ago   ENV NODE_ENV=production                         0B        buildkit.dockerfile.v0
    <missing>      About a minute ago   RUN /bin/sh -c apk add dumb-init # buildkit     1.65MB    buildkit.dockerfile.v0

Did you spot the secret npm token there? That’s what I mean.

There’s a great way to manage secrets for the container image, but this is the time to introduce multi-stage builds as a mitigation for this issue, as well as showing how we can build minimal images.

### Introducing multi-stage builds for Node.js Docker images

Just like that principle in software development of Separation of Concerns, we’ll apply the same ideas in order to build our Node.js Docker images. We’ll have one image that we use to build everything that we need for the Node.js application to run, which in a Node.js world, means installing npm packages, and compiling native npm modules if necessary. That will be our first stage.

The second Docker image, representing the second stage of the Docker build, will be the production Docker image. This second and last stage is the image that we actually optimize for and publish to a registry, if we have one. That first image that we’ll refer to as the `build` image, gets discarded and is left as a dangling image in the Docker host that built it, until it gets cleaned.

Here is the update to our Dockerfile that represents our progress so far, but separated into two stages:

    # --------------> The build image
    FROM node:latest AS build
    ARG NPM_TOKEN
    WORKDIR /usr/src/app
    COPY package*.json /usr/src/app/
    RUN echo "//registry.npmjs.org/:_authToken=$NPM_TOKEN" > .npmrc && \
       npm ci --omit=dev && \
       rm -f .npmrc
     
    # --------------> The production image
    FROM node:lts-alpine@sha256:b2da3316acdc2bec442190a1fe10dc094e7ba4121d029cb32075ff59bb27390a
    RUN apk add dumb-init
    ENV NODE_ENV production
    USER node
    WORKDIR /usr/src/app
    COPY --chown=node:node --from=build /usr/src/app/node_modules /usr/src/app/node_modules
    COPY --chown=node:node . /usr/src/app
    CMD ["dumb-init", "node", "server.js"]

As you can see, I chose a bigger image for the `build` stage because I might need tooling like `gcc` (the GNU Compiler Collection) to compile native npm packages, or for other needs.

In the second stage, there’s a special notation for the `COPY` directive that copies the `node_modules/` folder from the build Docker image into this new production base image.

Also, now, do you see that `NPM_TOKEN` passed as build argument to the `build` intermediary Docker image? It’s not visible anymore in the `docker history nodejs-tutorial` command output because it doesn’t exist in our production docker image.

## 9) Keeping unnecessary files out of your Node.js Docker images

You have a `.gitignore` file to avoid polluting the git repository with unnecessary files, and potentially sensitive files too, right? The same applies to Docker images.

Docker has a `.dockerignore` which will ensure it skips sending any glob pattern matches inside it to the Docker daemon. Here is a list of files to give you an idea of what you might be putting into your Docker image that we’d ideally want to avoid:

    .dockerignore
    node_modules
    npm-debug.log
    Dockerfile
    .git
    .gitignore

As you can see, the `node_modules/` is actually quite important to skip because if we hadn’t ignored it, then the simplistic Dockerfile version that we started with would have caused the local `node_modules/` folder to be copied over to the container as-is.

    FROM node@sha256:b2da3316acdc2bec442190a1fe10dc094e7ba4121d029cb32075ff59bb27390a
    WORKDIR /usr/src/app
    COPY . /usr/src/app
    RUN npm install
    CMD "npm" "start"

In fact, it’s even more important to have a `.dockerignore` file when you are practicing multi-stage Docker builds. To refresh your memory on how the 2nd stage Docker build looks like:

    # --------------> The production image
    FROM node:lts-alpine
    RUN apk add dumb-init
    ENV NODE_ENV production
    USER node
    WORKDIR /usr/src/app
    COPY --chown=node:node --from=build /usr/src/app/node_modules /usr/src/app/node_modules
    COPY --chown=node:node . /usr/src/app
    CMD ["dumb-init", "node", "server.js"]

The importance of having a `.dockerignore` is that when we do a `COPY . /usr/src/app` from the 2nd Dockerfile stage, we’re also copying over any local node\_modules/ to the Docker image. That’s a big no-no as we may be copying over modified source code inside `node_modules/`.

On top of that, since we’re using the wildcard `COPY .` we may also be copying into the Docker image sensitive files that include credentials or local configuration.

The take-away here for a `.dockerignore` file is:

- Skip potentially modified copies of `node_modules/` in the Docker image.
- Saves you from secrets exposure such as credentials in the contents of `.env` or `aws.json` files making their way into the Node.js Docker image.
- It helps speed up Docker builds because it ignores files that would have otherwise caused a cache invalidation. For example, if a log file was modified, or a local environment configuration file, all would’ve caused the Docker image cache to invalidate at that layer of copying over the local directory.

## 10) Mounting secrets into the Docker build image

One thing to note about the `.dockerignore` file is that it is an all or nothing approach and can’t be turned on or off per build stages in a Docker multi-stage build.

Why is it important? Ideally, we would want to use the `.npmrc` file in the build stage, as we may need it because it includes a secret npm token to access private npm packages. Perhaps it also needs a specific proxy or registry configuration to pull packages from.

This means that it makes sense to have the `.npmrc` file available to the `build` stage—however, we don’t need it at all in the second stage for the production image, nor do we want it there as it may include sensitive information, like the secret npm token.

One way to mitigate this `.dockerignore` caveat is to mount a local file system that will be available for the build stage, but there’s a better way.

Docker supports a relatively new capability referred to as Docker secrets, and is a natural fit for the case we need with `.npmrc`. Here is how it works:

- When we run the `docker build` command we will specify command-line arguments that define a new secret ID and reference a file as the source of the secret.
- In the Dockerfile, we will add flags to the `RUN` directive to install the production npm, which mounts the file referred by the secret ID into the target location—the local directory `.npmrc` file which is where we want it available.
- The `.npmrc` file is mounted as a secret and is never copied into the Docker image.
- Lastly, let’s not forget to add the `.npmrc` file to the contents of the `.dockerignore` file so it doesn’t make it into the image at all, for either the build nor production images.

Let’s see how all of it works together. First the updated `.dockerignore` file:

    .dockerignore
    node_modules
    npm-debug.log
    Dockerfile
    .git
    .gitignore
    .npmrc

Then, the complete Dockerfile, with the updated RUN directive to install npm packages while specifying the `.npmrc` mount point:

    # --------------> The build image
    FROM node:latest AS build
    WORKDIR /usr/src/app
    COPY package*.json /usr/src/app/
    RUN --mount=type=secret,mode=0644,id=npmrc,target=/usr/src/app/.npmrc npm ci --omit=dev
     
    # --------------> The production image
    FROM node:lts-alpine
    RUN apk add dumb-init
    ENV NODE_ENV production
    USER node
    WORKDIR /usr/src/app
    COPY --chown=node:node --from=build /usr/src/app/node_modules /usr/src/app/node_modules
    COPY --chown=node:node . /usr/src/app
    CMD ["dumb-init", "node", "server.js"]

And finally, the command that builds the Node.js Docker image:

    docker build . -t nodejs-tutorial --secret id=npmrc,src=.npmrc

**Note:** Secrets are a new feature in Docker and if you’re using an older version, you might need to enable it Buildkit as follows:

    DOCKER_BUILDKIT=1 docker build . -t nodejs-tutorial --build-arg NPM_TOKEN=1234 --secret id=npmrc,src=.npmrc
