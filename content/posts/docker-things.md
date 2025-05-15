+++
date = '2025-05-14T19:40:14+02:00'
title = 'Docker Things'
categories = ["school", "linux", "docker"]
tags = ["linux","docker","school","devops"]
+++

> The code for all setups is available on my GitHub [here](https://github.com/Stefanistkuhl/goobering/tree/master/things/silly_docker_guide).

# Docker crash course

## What is docker?

> Docker is an open platform for developing, shipping, and running applications. Docker enables you to separate your applications from your infrastructure so you can deliver software quickly. With Docker, you can manage your infrastructure in the same ways you manage your applications. By taking advantage of Docker's methodologies for shipping, testing, and deploying code, you can significantly reduce the delay between writing code and running it in production.

## Why use it?


- Makes building and running apps easier and faster
  - Keeps the app separate from the computer it runs on, so it works the same anywhere (your PC, a server, or the cloud)
  - Helps you update and deliver new versions quickly
  - Makes sure the app runs the same every time, no matter where it’s deployed
  - Saves time when moving from writing code to actually using it

- Lets you use and manage different versions of software
  - You can run older or specific versions of apps without messing up your system
  - Useful if your project needs a tool that only works with a certain version

- Runs apps in isolated containers
  - Each app runs in its own “box,” separate from others, which makes it safer and easier to manage
  - You can test apps without affecting the rest of your system

- Great for home setups and personal servers
  - Run things like a media server (e.g. Jellyfin), game server, or home automation tools (e.g. Home Assistant) in containers
  - Keeps each service isolated, so if one breaks, the others keep working
  - Easy to back up, move, or update your services



## How does it work?

### Docker vs VMS

Both technologies aim to achieve a similar goal: providing an isolated environment to deploy applications. However, they do it differently-containers share the host system’s operating system, while virtual machines run their own full operating systems using a hypervisor.

- Startup Time
    - Containers: Start in seconds.
    - VMs: Can take up to minutes to boot.
- Resource Usage
    - Containers: Very light weight.
    - VMs: Require more processing power.
- Storage Size
    - Containers: from a few MBs to a few hundres.
    - VMs: several GBs.
- Operating System
    - Containers: Share the host OS kernel.
    - VMs: Each has its own full OS.
- Portability
    - Containers: Made to be moved and deployed everywhere
    - VMs: Slow to migrate due to large sizes
![](https://media.geeksforgeeks.org/wp-content/uploads/20230109130229/Docker-vs-VM.png)
Image from [Geeks for Geeks](https://www.geeksforgeeks.org/docker-or-virtual-machines-which-is-a-better-choice/)


## Docker ussage basics

To demonstrate the basic uses of Docker, I will deploy the same simple Go and HTML app five times. First, I'll deploy it without Docker to show how it works normally. Then, I'll build custom Docker containers for the backend and frontend. Next, I'll use Docker Compose, followed by deploying it on a remote host using Docker Context. Finally, I'll use Docker Swarm with a Docker Stack to enable replicas and orchestration.

### Deploying without Docker

I created a simple Go web server with one API endpoint. This endpoint is called by JavaScript in an HTML file, which is served by Nginx. Nginx also handles routing to the API.
To deploy this, I need to run the Go server, configure Nginx, and place the HTML file in the correct location. Here's the current structure of my project:
```
├── backend
│   ├── go.mod
│   └── main.go
├── frontend
│   └── index.html
└── nginx
    └── nginx.conf
```
To simplify setup, I created a symbolic link from my custom Nginx config to the system config path using:

`sudo ln -s /full/path/to/your/nginx.conf /etc/nginx/nginx.conf`

Normally, Nginx configs should be split into separate files per site (virtual hosts), but since I'm only hosting this one project, I modified the main config directly. Note: this is not best practice, but it's acceptable for quick testing.
I also symlinked the index.html file to Nginx’s web root so it can serve it:

`sudo ln -s /full/path/to/your/index.html /usr/share/nginx/html/index.html`

Now, by opening a terminal in the backend directory and running:

`go run main.go`

...and enabling Nginx using systemd or another method, I can visit localhost in a browser and see the webpage. If I want to make changes, I can edit the HTML file and refresh the page, or update the Go code, stop the server, and run it again.
While this setup might work fine for local development, it's too much hassle to repeat for every project. As soon as you need to collaborate with others or deploy to a server, it becomes inefficient and error-prone.
For example, to deploy this on a remote server, I’d have to manually copy the files, place them in the right locations, and start the services. I’d also have to repeat this process for every update—which is awful.

### Using Docker

Now let’s use Docker to deploy this app and demonstrate the basic features needed to create, deploy, and manage containers—improving the deployment with each iteration.
Updated Directory Structure

First, I changed the directory structure to include a Dockerfile for the backend. This file contains instructions that Docker uses to build an image, which can then be deployed as a container.

```
├── backend
│   ├── Dockerfile
│   ├── go.mod
│   └── main.go
├── frontend
│   └── index.html
└── nginx
    └── nginx.conf
```
Let’s examine the `Dockerfile` to understand how a container is built:
```Dockerfile
FROM golang:1.22-alpine

WORKDIR /app

COPY . .

RUN go build -o main .

EXPOSE 3000

CMD ["./main"]
```
### Explanation of Each Dockerfile Instruction

- **`FROM golang:1.22-alpine`**  
  Every `Dockerfile` starts with the `FROM` instruction, which specifies the **base image**. In this case, we’re using Go version 1.22 on Alpine Linux. Alpine is a minimal Linux distribution designed for containers and is only a few hundred megabytes in size.

- **`WORKDIR /app`**  
  This sets the working directory inside the container. All subsequent instructions will be executed from this directory unless changed.

- **`COPY . .`**  
  This copies all files from the current host directory (where the Dockerfile is located) into the working directory of the container. You could also list specific files instead. To exclude files or folders, you can use a `.dockerignore` file in the same directory.

- **`RUN go build -o main .`**  
  This command compiles the Go source code into a binary named `main`.

- **`EXPOSE 3000`**  
  This tells Docker that the application listens on port 3000. It doesn’t actually expose the port when running the container—it just documents the port for later mapping.

- **`CMD ["./main"]`**  
  This defines the default command to run when the container starts. In this case, it runs the compiled Go binary.

> The resulting image is about 303 MB in size. This could be significantly reduced by using a **multi-stage build**—first using the base image with the OS and Go tools to compile the binary, and then copying just the compiled binary into a minimal final image. Since this process is straightforward and well-documented, I chose not to cover it in detail here to keep things focused.

To actually build this container, the following command is used:

```bash
docker buildx build -t manual-backend backend
```

This command uses the `buildx` subcommand and the `-t` flag to tag (name) the image being built. The last part, `backend`, specifies the build context — in this case, the directory where the `Dockerfile` and required files are located.

Once the image is built, we can run the container using:

```bash
docker run manual-backend
```

This will start the container, but it will stop as soon as we press `Ctrl+C`. To keep it running in the background, we use the `-d` flag to run it in detached mode. We can also name the container using the `--name` flag.

Additionally, we need to map port `3000` from the container to the host using the `-p` option so that we can actually access the application. If we use a capital `-P` instead of a lowercase `-p`, Docker will map a random port on the host to the default exposed port of the container.

```bash
docker run -d -p 3000:3000 --name manual-backend manual-backend:latest
```

Now we can list all running containers using:

```bash
docker ps
```

This will display the container's name and hash ID, which can be used to identify it.

To view logs from the container, use:

```bash
docker logs [CONTAINER_NAME or CONTAINER_ID]
```

If we want to connect to the container's shell, we can use:

```bash
docker exec -it [CONTAINER_NAME] sh
```

The `-i` and `-t` flags make the shell interactive with a TTY. This works because the container runs a full Alpine Linux system — if we had optimized the container to include only the compiled binary, this wouldn’t be possible.

To stop the container:

```bash
docker stop [CONTAINER_NAME or CONTAINER_ID]
```

To start it again:

```bash
docker start [CONTAINER_NAME or CONTAINER_ID]
```

To remove it:

```bash
docker rm [CONTAINER_NAME or CONTAINER_ID]
```

To remove all stopped containers:

```bash
docker container prune
```

Now only the backend is running inside a container, but we still need to package the frontend as well. For this step, we won’t build a custom image yet. Instead, we’ll use a single `docker run` command:

```bash
docker run -d --name manual-frontend -p 8080:80 \
    -v "$(pwd)"/nginx/frontend/index.html:/usr/share/nginx/html/index.html \
    -v "$(pwd)"/nginx/nginx.conf:/etc/nginx/conf.d/nginx.conf:ro \
    nginx:alpine
```

This command is a bit more complex since more things are happening:

- First, we map port `8080` on the host to port `80` in the container using the `-p` option. This allows us to access the application through the browser. We use `8080` on the host to avoid conflicts with existing services, so we don’t need to change the default `nginx` configuration.
  
- Then, we use the `-v` flag (short for volume) to bind files from the host into the container. This way, we can edit the HTML file on the host and see the changes instantly in the container. The same applies to the Nginx configuration file, although changes to the config will require restarting the container. This method avoids the need to build a custom Docker image for now.

- Finally, we specify the image to use: `nginx:alpine`, which is an official, lightweight image from the Docker registry.

With both containers running, you can open `http://localhost:8080` in your browser and see the application working.

However, this method is still very inconvenient, which brings us to the next improvement in deploying our app.

## Docker compose

To make multi-container deployments easily manageable, Docker offers **Docker Compose**, which allows you to define and control multiple containers using a single configuration file.

To do this, create a file called `docker-compose.yml`.

Let’s break down the structure of this file for our service:

```yml
services:
  backend:
    image: backend:latest
    build: 
      context:
        ./backend
  frontend:
    image: nginx:alpine
    ports:
      - "8080:80"
    volumes:
      - ./nginx/frontend/index.html:/usr/share/nginx/html/index.html
      - ./nginx/nginx.conf:/etc/nginx/conf.d/nginx.conf:ro
    depends_on:
      - backend
  ```
The file starts with the `services` keyword, which defines each of the containers we want to run as attributes. Each container then has its own child attributes for configuration.

We begin by defining our backend container using the `backend:` key. We specify the image it should use — in this case, `backend`, which is the name we give it after building. To tell Docker Compose to build this image, we use the `build:` keyword and provide the `context:` attribute, which points to the path where the Dockerfile and source files are located.

Next, we define the frontend container, using the `nginx:alpine` image. We expose the necessary ports and bind the required files using volumes. This is much more manageable than writing out long `docker run` commands and is far easier to maintain.

We also use the `depends_on` option to ensure the frontend container only starts once the backend container is up and running. This helps guarantee that the application functions correctly without manual timing issues.

Additionally, we don’t need to publish any ports on the backend container. When using Docker Compose, a default Docker network is created for the containers in the stack. This allows containers to resolve each other by name, making internal communication seamless. For example, the frontend can reach the backend simply by using the container name as the hostname. This also means the backend doesn't need to be exposed to the outside world, which improves security by ensuring it can only be accessed through the frontend, without needing to configure firewalls or restrict public access manually.

Now, to deploy this, simply run:

```bash
docker compose up -d --build
```

This command builds all the images and deploys the containers. That’s it — you can just open your web browser and test everything. Thanks to volume mapping, any changes made to the HTML file will carry over immediately after a page reload.

You can inspect logs from the containers using:

```bash
docker compose logs
```

To see the running containers, use:

```bash
docker compose ps
```

To stop and remove all containers, use:

```bash
docker compose down
```

If you run `docker compose up -d --build` again afterward, the containers will be rebuilt and restarted — but they remain running during the build process to minimize downtime. Only the containers with actual changes will be replaced.

This setup now provides a very usable and portable local development environment that's easy to manage. However, it still lacks production-readiness since deploying to a server still requires SSH access and copying the files over manually or pulling them from a Git repository.

That brings us to the next two improvements, which will be discussed in the following section.

### Docker Context

## Docker Context

Docker Context is a way to run Docker commands on a remote host **without needing to SSH** into your server like it's the stone age.

To add a server via SSH as a Docker context (assuming you have SSH key authentication already set up so no password prompt appears for each command), you can use the following command:

```bash
docker context create context_name --docker "host=ssh://user@ip_address"
```

> **Note:** The `host` value doesn't have to be an IP address — it could also be a Unix socket or another Docker-compatible host. SSH is just one method.

### Managing Contexts

- To list all available contexts:  
  ```bash
  docker context ls
  ```

- To switch to a specific context:  
  ```bash
  docker context use [CONTEXT_NAME]
  ```

- To remove a context:  
  ```bash
  docker context rm [CONTEXT_NAME]
  ```

To see which context is currently active, run `docker context ls`. The active one will be marked with a `*`. If you're using the **Starship** prompt, it will display the active Docker context just like it shows the current Git branch or programming language.

Once a context is selected, **all Docker commands will be executed on the remote machine** instead of your local system.

---

However, if you run `docker compose up -d --build` on the remote host now, you'll likely get an error about missing files used in volume mounts. This happens because the volume mounts are referencing local paths that don’t exist on the remote host.

To fix this, we’ll need to change the `docker-compose` file in the next step.


#### Overwriting compose files and optizing the setup

To fix this issue, let's make a duplicate of the compose file and name it `compose.dev.yml`. We can then change our main compose file to the settings we want for deployment.
I updated the compose file as follows:
```yml
services:
  backend:
    image: backend:latest
    build: 
      context:
        ./backend

  frontend:
    image: frontend:latest
    build:
      context:
        ./nginx
    ports:
      - "8080:80"
    depends_on:
      - backend
```
Prior to this, we were mapping the files into the container using volumes. Now, instead, a new frontend image is built which copies the HTML and the Nginx configuration directly into the image.

In a production environment, you don't need the ability to update files live, so this makes the deployment more stable and less prone to accidental breakage. The new frontend image has the following contents:
```Dockerfile
FROM nginx:alpine

RUN rm /etc/nginx/conf.d/default.conf

COPY nginx.conf /etc/nginx/conf.d/

COPY frontend /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
```
It takes the Alpine Nginx image as a base, removes the default configuration, replaces it with the new one, copies the HTML file, sets the port to listen on, and defines the entry command.

Now, to still have a nice way to run the development version locally, the file from before comes into play, which has the following contents:

```yml
services:
  frontend:
    image: nginx:alpine
    ports:
      - "8080:80"
    volumes:
      - ./nginx/frontend/index.html:/usr/share/nginx/html/index.html
      - ./nginx/nginx.conf:/etc/nginx/conf.d/nginx.conf:ro
    depends_on:
      - backend
```
It currently only has the original frontend service. If we run `docker compose` with the `-f` option to specify multiple files — such as the original and a new override file — the second file will overwrite any matching sections (like `frontend`). This allows us to use the development version of the frontend.

The command would look like this:

```bash
docker compose -f docker-compose.yml -f compose.dev.yml up -d
```

After all these changes, this is the current directory structure of the project:

```
├── backend
│   ├── Dockerfile
│   ├── go.mod
│   └── main.go
├── compose.dev.yml
├── docker-compose.yml
└── nginx
    ├── Dockerfile
    ├── frontend
    │   └── index.html
    └── nginx.conf
```

Now we can deploy both a development and a production version of our app to a remote server — which is already a solid place to stop for many small projects. 

But to take it one step further, let's add **orchestration** to support **replicas** and **multiple servers**. This allows us to **scale** our application, **balance traffic**, and improve **fault tolerance** by ensuring that if one container or server fails, others can continue handling requests.


## Docker Swarm

Docker Swarm is a built-in container orchestrator for Docker that is simple to use yet powerful. It is very useful in a home lab environment since Kubernetes would be overkill, but it's also viable for small businesses and their production environments.

### What is Container Orchestration?

A good analogy is that container orchestration is like an orchestra where all the containers and services are the musicians playing instruments. The conductor (orchestrator) manages and syncs the musicians so a song is played instead of a mess.

The conductor — the master/control node — can replicate containers to scale the app, remove unhealthy ones, replace failed containers, and keep the app stable, running, and available.

### Creating a Docker Swarm

Creating a Docker Swarm is simple: just run
```bash
docker swarm init
````

on the device you want to be the master node.

After this, you can check the swarm status with:

```bash
docker info
```

which will show that the node is now part of a swarm.

### Adding Nodes

To add nodes to the cluster, copy the command shown after `docker swarm init` and run it on another Docker host to join it to the cluster. On the master node, running

```bash
docker info
```

will show multiple nodes, and

```bash
docker node ls
```

will list all the nodes in the swarm.

Nodes can leave the cluster with:

```bash
docker swarm leave
```

Now the cluster is ready for deploying services.

### Creating a Stack

Since we are using Swarm, we can no longer use plain `docker compose` commands; instead, we use `docker stack` commands.
`docker stack` uses the same Compose file format with some additional deployment options, but build options are not supported — images must be pre-built.

```yml
services:
  backend:
    image: 127.0.0.1:5000/swarm-backend:latest
    build: 
      context:
        ./backend
    deploy:
      replicas: 3

  frontend:
    image: 127.0.0.1:5000/swarm-frontend:latest
    build:
      context:
        ./nginx
    ports:
      - "8080:80"
    depends_on:
      - backend
    deploy:
      replicas: 2
```
Now we can specify in the Compose file how many replicas we want for each container. The new addition is the `image` part, which will be explained in the next section because `docker stack` cannot build your containers directly — it requires already built images.

We can deploy this stack with:
```bash
docker stack deploy -c docker-compose.yml [STACK_NAME]
````

Like Compose, this will create a network, but this time it deploys to our swarm cluster with the specified replicas.

With

```bash
docker service ls
```

we can see running services, whether they are replicated, and how many replicas are currently running. Docker dynamically spins containers up or down based on demand, which can be configured.

---

### Creating a Local Registry

To clarify the `image` part mentioned above where a local registry is used: this is needed so the built images can be used by the swarm stack.

To create a local registry, run:

```bash
docker service create --name registry --publish=5000:5000 registry:2
```

Now we can use the local registry with `localhost:5000` in the Compose file image tags.

You build images with:

```bash
docker compose build
```

and push them to the registry with:

```bash
docker compose push
```

so they can be used in the stack.

These are just two extra commands, but for production deployments you can set up CI/CD pipelines to do this automatically whenever you push to your git repository and update the running version without running Docker commands manually.

You can still run everything locally with:

```bash
docker compose up -d
```

to test the full setup.

---

### Scaling the Service

To manually scale a service, you can use the command:

```bash
docker service scale backend=10
```

which would spin up 10 replicas of the `backend` service distributed across your nodes.

You can check which containers are running on which nodes with:

```bash
docker stack ps [STACK_NAME]
```

to see their state and placement.

You can further configure how nodes are scaled based on resources and other factors, but I will stop here. The main goal is to show the power and value of Docker and leave the rest of the learning to you. This gives you a working setup you can expand on to gain more experience.

> Note:
> I changed the app to assign a random color based on the hostname so that when it is scaled up, you can visually see that different containers are handling your connections.

The code for all setups is available on my GitHub [here](https://github.com/Stefanistkuhl/goobering/tree/master/things/silly_docker_guide).

Thanks for reading! :3

> TODO: Add citations to this at some point, include screenshots for examples, and add more info over time so this becomes a real blog post and not just notes for myself.
