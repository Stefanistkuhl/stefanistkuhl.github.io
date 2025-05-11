+++
date = '2025-01-04T03:33:09+01:00'
title = 'Hardening a Linux Webserver'
categories = ["school", "it sec"]
tags = ["linux","it sec","school","blue team"]
+++

> Note: this was converted from LaTeX to Markdown using ChatGPT 4.1. The original PDF can be found [here](https://github.com/Stefanistkuhl/goobering/blob/master/itsi/y3/ex6/GNU_Linux_Securing_Active_Components.pdf) along with the [bibliography](https://github.com/Stefanistkuhl/goobering/blob/master/itsi/y3/ex6/quellen.bib).

---

# Exercise 6: GNU/Linux - Securing active components

---

**Laboratory protocol**  
Exercise 6: GNU/Linux - Securing active components  
{{< figure src="/itsi/y3/ex6/images/mika.png" title="Figure: Grouplogo" >}}
**Subject:** ITSI  
**Class:** 3AHITN  
**Name:** Stefan Fürst, Marcel Raichle  
**Group Name/Number:** Team 7/7  
**Supervisor:** SPAC, ZIVK  
**Exercise dates:** 6.12.2024, 13.12.2024, 20.12.2024, 3.1.2025, 4.1.2025, 5.1.2025  
**Submission date:** 4.1.2025

---

## Table of Contents

- [Task definition](#task-definition)
  - [Task 0 - Preparation](#task-0---preparation)
  - [Task 1 – Installing a Web Server](#task-1--installing-a-web-server)
  - [Task 2 – Securing with Basic Authentication](#task-2--securing-with-basic-authentication)
  - [Task 3 – Encrypting with HTTPS](#task-3--encrypting-with-https)
  - [Bonus Task – Local DNS Setup (Optional)](#bonus-task--local-dns-setup-optional)
- [Summary](#summary)
- [Complete network topology of the exercise](#complete-network-topology-of-the-exercise)
- [Exercise Execution](#exercise-execution)
  - [Preparation](#preparation)
    - [Testing the SSH connectivity](#testing-the-ssh-connectivity)
    - [Changes to the Docker setup](#changes-to-the-docker-setup)
  - [Installing an active component](#installing-an-active-component)
    - [Setting up PHP-FPM with Nginx](#setting-up-php-fpm-with-nginx)
  - [Securing Nginx with Basic Authentication](#securing-nginx-with-basic-authentication)
    - [Creating a Password File](#creating-a-password-file)
    - [Configuring the authentication in Nginx and testing it](#configuring-the-authentication-in-nginx-and-testing-it)
  - [Configuring HTTPS with Self-Signed Certificates](#configuring-https-with-self-signed-certificates)
  - [Adding a Domain](#adding-a-domain)
- [References](#references)

---

## Task definition

**Task 0 - Preparation**  
Ensure your server from Exercises 4 and 5 is configured with SSH. Verify that you can connect to the server via SSH using a client with a GUI.

**Task 1 – Installing a Web Server**  
Install a web server (e.g., Apache or Nginx) and deploy a static HTML page displaying your group number, team members, and an AI-generated image. (Bonus: Deploy a dynamic PHP page.) Demonstrate access to the page from a client browser.

**Task 2 – Securing with Basic Authentication**  
Set up Basic Authentication on the server. Create user accounts in the format `nnv-webuser` and for your instructors (e.g., `zivk-webuser`). Demonstrate authentication functionality. (Bonus: Capture the password using Wireshark.)

**Task 3 – Encrypting with HTTPS**  
Enable HTTPS with a self-signed certificate, including your group number. Demonstrate encrypted access and explain potential issues. Install the certificate on a client to show why this action is not required in the public internet.

**Bonus Task – Local DNS Setup (Optional)**  
Set up DNS on the server using `bind9` for local access via `xxx.itsi3.local`. Demonstrate DNS resolution and access the website by domain name.<cite>ChatGPT[^1]</cite>

---

## Summary

As preparation for the exercise, I optimized the Docker workflow by using Docker Compose for easier management, improved the readability of the Dockerfile, and, most importantly, created a `.env` file along with a build script that utilizes it, so I no longer hardcode my passwords in the Dockerfile. Additionally, I disabled password authentication and now copy the `authorized_keys` file into the container, allowing for key-based authentication from the start and enabling me to disable password authentication.

We need to install a web server, for which I chose `nginx`. I used it in conjunction with `php-fpm` to deploy a dynamic PHP webpage. The webpage includes our group number, names, and an AI-generated image. However, since this information should only be accessible with credentials, I implemented Basic Authentication to secure it. For this, the `apache2-utils` package was used to generate a `.htpasswd` file containing the credentials.

We demonstrated with Wireshark that the credentials were transmitted in plain text while using HTTP. To address this, a self-signed SSL certificate was generated using `openssl`, with the group number included in the `OU` field of the certificate. The server was then configured to use HTTPS. We showed that the credentials could no longer be read with Wireshark, as the traffic was now encrypted.

Lastly, we set up a domain, created a DNS record to point to the server, and generated a proper SSL certificate with Let's Encrypt, ensuring it is trusted and does not display a warning in the browser.

---

## Complete network topology of the exercise

{{< figure src="/itsi/y3/ex6/images/topology.png" title="Figure 1: Network topology of this exercise" >}}

---

## Exercise Execution

### Preparation

The requirements for this exercise are a headless Linux server with hardened SSH, which only allows connections via key pairs. However, I removed the OTP authentication added in the last exercise, as it was overkill for this use case and became a burden to use.

{{< figure src="/itsi/y3/ex6/images/sshnopw.png" title="Figure 2: Password authentication disabled" >}}

#### Testing the SSH connectivity

{{< figure src="/itsi/y3/ex6/images/nokey.png" title="Figure 3: No SSH key available" >}}
{{< figure src="/itsi/y3/ex6/images/yeskey.png" title="Figure 4: ram-fus authenticating via SSH key" >}}
{{< figure src="/itsi/y3/ex6/images/yeskey2.png" title="Figure 5: ram-ram authenticating via SSH key" >}}

---

#### Changes to the Docker setup

To improve the quality of life when working on this project, I switched from aliasing a long and hard-to-read run command to using Docker Compose, which allows you to define and run multi-container applications. Since it's in a YAML file, it is more readable and easier to work with, even in this use case where I only have one container.<cite>Docker-Compose[^2]</cite>

```yaml
services:
    webserver:
        container_name: itsi
        image: itsi:latest
        restart: no
    ports:
        - "38452:38452"
        - "80:80"
        - "443:443"
```

Furthermore, instead of having all of the credentials in the Dockerfile, I created a `.env` file in which the passwords are set. To utilize that, I made a build script that passes the variables from the file to the Dockerfile.<cite>docker-arg[^3]</cite>

```bash
#!/bin/bash
export $(cat .env | xargs)

docker buildx build -t itsi:latest\
	--build-arg ROOT_PW=$ROOT_PW \
	--build-arg RAM_WEBUSER_PW=$RAM_WEBUSER_PW \
	--build-arg ZIVK_WEBUSER_PW=$ZIVK_WEBUSER_PW \
	--build-arg RAM_FUS_PW=$RAM_FUS_PW \
	--build-arg RAM_RAM_PW=$RAM_RAM_PW \
	--build-arg RAM_ALOIS_PW=$RAM_ALOIS_PW \
	--build-arg RAM_CHRIS_PW=$RAM_CHRIS_PW \
	--build-arg RAM_BERTA_PW=$RAM_BERTA_PW .
```

These build-time arguments are referenced in the Dockerfile like this:

```dockerfile
ARG ROOT_PW
ARG RAM_WEBUSER_PW
ARG ZIVK_WEBUSER_PW
ARG RAM_FUS_PW
ARG RAM_RAM_PW
ARG RAM_ALOIS_PW
ARG RAM_CHRIS_PW
ARG RAM_BERTA_PW
...
RUN echo 'root:$ROOT_PW' | chpasswd
...
```

Here is what the `.env` file looks like for this project:

```
ROOT_PW='some password'
...
```

Note that the quotes are only necessary if the password contains characters like `&`, which the shell will interpret.

With this change, I can add the `.env` file to my `.gitignore` file so I don't accidentally commit my passwords again and handle passwords in a Dockerfile properly.

To still utilize my alias script, I changed every instance of `docker run` to `docker compose up -d`, `docker stop itsi && docker rm itsi` to `docker compose down`, and added the use of the build script to it.

```bash
#!/bin/bash
alias relaunch="sh -c 'docker stop itsi && docker rm itsi &&\
		       ./build.sh &&\
		       docker compose up -d && docker exec -it itsi /bin/bash'"
alias rebuild="sh -c './build.sh &&\
                      docker compose up -d && docker exec -it itsi /bin/bash'"
alias stop="sh -c 'docker compose down'"
```

Furthermore, instead of having to upload my container every time I rebuild, I added these three lines to copy the `authorized_keys` file with the devices I use to the container, so that every time I relaunch, I can just immediately SSH into it.

```dockerfile
COPY ./mapped-files/authorized_keys /root/.ssh/authorized_keys
COPY ./mapped-files/authorized_keys /home/ram-fus/.ssh/authorized_keys
COPY ./mapped-files/authorized_keys /home/ram-ram/.ssh/authorized_keys
```

Lastly, the line in the Dockerfile that specifies the exposed ports is edited to expose ports 80 and 443, as they will be required for this exercise.

```dockerfile
EXPOSE 38452 80 443
```

---

### Installing an active component

Now, it's required to install a web server. I chose Nginx because I am most familiar with it, and due to its high performance and simplicity of use.

```dockerfile
RUN apt install -y nginx
...
CMD service ssh start && service nginx start && tail -F /dev/null
```

After modifying the Dockerfile, rebuilding, and redeploying, if we now open the web browser and go to the server's IP, we see the following.

{{< figure src="/itsi/y3/ex6/images/nginx.png" title="Figure 6: Default nginx site" >}}

The HTML site displayed is located at `/var/www/html/index.nginx-debian.html`.  
Additionally, I replaced the `/var/www/html` directory with `/var/www/metyr.xyz`, in which I have the following file structure:

```bash
`-- html
   |-- private
   |   `-- private.php
    `-- public
        `-- index.php
```

These two directories are mapped onto the Docker container in the `docker-compose.yml` file, as shown below. Since they are mapped, every time the files are changed on the host, the changes carry over to the container, allowing for an easy and fast development workflow without the need to exec into the container or copy the files when creating the image.

```yaml
volumes:
    - ./mapped-files/public:/var/www/html/public:rw
    - ./mapped-files/private:/var/www/html/private:rw
```

Additionally, I edited the Dockerfile to delete the default Nginx configuration file, located at `/etc/nginx/sites-enabled/default`, a symlink to the file `/etc/nginx/sites-available/default.conf`, and replaced it with one matching my domain name for better readability.

```dockerfile
RUN rm -rf /var/www/html/
RUN mkdir -p /var/www/metyr.xyz/html
RUN rm /etc/nginx/sites-available/default
RUN rm /etc/nginx/sites-enabled/default
COPY ./mapped-files/metyr.xyz /etc/nginx/sites-available/metyr.xyz
RUN ln -s /etc/nginx/sites-available/metyr.xyz /etc/nginx/sites-enabled/metyr.xyz
```

---

#### Setting up PHP-FPM with Nginx

To give Nginx the ability to serve PHP files, the `php-fpm` (FastCGI Process Manager) package is required.

```nginx
server{
	...
	index public/index.php;
	location ~ \.php$ {
		include snippets/fastcgi-php.conf;
		fastcgi_pass unix:/run/php/php8.3-fpm.sock;
	}
	...
}
```

Additionally, the `php-fpm` service has to be started, so the default command of the container is edited.

```dockerfile
CMD service ssh start && service nginx start && service php8.3-fpm start && tail -F /dev/null
```

If we now rebuild the container, deploy it, and go to the IP address of the server in the browser, we can see the PHP page displayed.

{{< figure src="/itsi/y3/ex6/images/indexphp.png" title="Figure 7: Viewing the index of the website" >}}
{{< figure src="/itsi/y3/ex6/images/privatphp.png" title="Figure 8: Viewing the private part of the website" >}}

---

### Securing Nginx with Basic Authentication

To restrict access to the website or certain parts of it by implementing username/password authentication, a file containing usernames and passwords is required. This file can be generated using tools such as `apache2-utils`, which I will use for this exercise.<cite>nginx-basic-auth[^3]</cite>

#### Creating a Password File

With `apache2-utils` installed, we can now generate a password file by using the `htpasswd` command with the `-c` flag to create a new file. The file path is specified as the first argument, and the username is specified as the second argument. However, to avoid having to manually type in the password, the `-i` flag is used to take the password from `stdin`, which we pass using `echo`, while using the `-n` flag to remove the trailing newline.<cite>htpasswd[^4]</cite><cite>echo-mangapge[^5]</cite>

```bash
RUN echo -n "$RAM_WEBUSER_PW" | htpasswd -i -c /etc/apache2/.htpasswd ram-webuser
RUN echo -n "$ZIVK_WEBUSER_PW" | htpasswd -i /etc/apache2/.htpasswd zivk-webuser
```

#### Configuring the authentication in Nginx and testing it

To require authentication for a specific area on the website, we need to create a location block that matches everything in the `/private` directory. To do this, Nginx URL matching is used.<cite>Nginx-url-matching[^6]</cite>

```nginx
location ^~ /private {
	include snippets/fastcgi-php.conf;
	fastcgi_pass unix:/run/php/php8.3-fpm.sock;
	auth_basic "Private Area";
	auth_basic_user_file /etc/apache2/.htpasswd;
}
```

To visualize testing the login, I added this to the private PHP page to show the currently logged-in user:  
`<h3>Hello <?php echo $_SERVER['PHP_AUTH_USER']; ?></h3>`.<cite>php-show-basic-auth[^7]</cite>

{{< figure src="/itsi/y3/ex6/images/siginprompt.png" title="Figure 9: Showing the sign-in prompt" >}}
{{< figure src="/itsi/y3/ex6/images/noauth.png" title="Figure 10: Failed authentication" >}}
{{< figure src="/itsi/y3/ex6/images/zivk_webuser.png" title="Figure 11: Logged in as zivk-webuser" >}}
{{< figure src="/itsi/y3/ex6/images/ram_webuser.png" title="Figure 12: Logged in as ram-webuser" >}}

This is still only an HTTP site, though, which means that everything is transmitted in plain text. As a result, with a packet analyzer like Wireshark, the clear-text login credentials can be viewed. To fix this, HTTPS needs to be enabled, which will be covered in the next section.

{{< figure src="/itsi/y3/ex6/images/zivk_snifa.png" title="Figure 13: Reading the plaintext credentials of zivk-webuser" >}}
{{< figure src="/itsi/y3/ex6/images/ram_snifa.png" title="Figure 14: Reading the plaintext credentials of ram-webuser" >}}

---

### Configuring HTTPS with Self-Signed Certificates

To stop an attacker from being able to read the credentials, HTTPS needs to be enabled on the server to encrypt the HTTP traffic with TLS (Transport Layer Security). Before this can be set up, an SSL certificate must first be created.<cite>self-signed-ssl[^8]</cite><cite>non-interactive-ssl-gen[^9]</cite>

```bash
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/nginx-selfsigned.key \
    -out /etc/ssl/certs/nginx-selfsigned.crt \
    -subj "/C=AT/ST=Vienna/L=Vienna/O=RAM/OU=7/CN=metyr.xyz/emailAddress=wedm1ebmf@mozmail.com"
```

Now, in the Nginx configuration file, we need to make the server listen on port 443 and add the SSL certificate and key.

```nginx
server{
	...
	listen 443;
	listen [::]:443;
	ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
	ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
	...
}
```

After setting up HTTPS, it's recommended to set up a 301 HTTP redirect to direct HTTP traffic to the HTTPS site. This is done by adding a second server block at the end of the nginx config file.

```nginx
server {
	listen 80;
	listen [::]:80;
	server_name _;
	return 301 https://$server_name$request_uri;	
}
```

If we reload the Nginx configuration, our browser is going to give us a security warning since it recognizes that the certificate was not signed by a trusted organization but by ourselves.

{{< figure src="/itsi/y3/ex6/images/unseccert.png" title="Figure 15: Browser warning for untrusted certificate" >}}
{{< figure src="/itsi/y3/ex6/images/selfcert.png" title="Figure 16: Viewing the self-signed certificate" >}}

If we open up Wireshark and inspect our traffic, we can see that we can't view any HTTP traffic. Instead, we only see TLS packets, which contain the encrypted HTTP data, and therefore the credentials can't be viewed anymore.

{{< figure src="/itsi/y3/ex6/images/nohaxxor.png" title="Figure 17: Not being able to see the credentials anymore" >}}

---

### Adding a Domain

Since I am doing this on a public VPS, I can't use a local DNS and need to use a real domain instead. I bought `metyr.xyz` from [Namecheap](https://www.namecheap.com/).

To make Nginx use the domain name, you have to set the `server_name` in the configuration from `server_name _;` to `server_name metyr.xyz www.metyr.xyz;`.

Now we need to create a DNS record for our domain.

This record needs to be of the `A` type, which returns a 32-bit IPv4 address and is commonly used to map hostnames to an IP address.<cite>dns-record-types[^10]</cite> The `@` in the Host field is used to denote the current origin, which represents the current domain. In this case, it would be `metyr.xyz`.<cite>rfc[^11]</cite>

{{< figure src="/itsi/y3/ex6/images/dnsentry.png" title="Figure 18: Setting up the DNS record" >}}

Lastly, I want to switch from using a self-signed certificate to using an officially signed one by Let's Encrypt. For this, the `certbot` and `python3-certbot-nginx` packages need to be added to our system.

Now we can run this command to generate an SSL certificate, which will be signed by Let's Encrypt, so the browser won't give us a security warning anymore.

```bash
certbot --nginx -d metyr.xyz --non-interactive --agree-tos -m wedm1ebmf@mozmail.com
```
<cite>certbot-options[^12]</cite>

After running this command for the first time and replying if you haven't saved the certificate, you can use the `--force-renewal` flag to forcefully renew the certificate in case you lost it or don't want to set up importing it on a rebuild.<cite>cerbot-force-newnew[^13]</cite>

If we visit the website now, we can see that we won't be prompted with a security warning. If we inspect the certificate, it will show that it was issued by Let's Encrypt and is trusted.

{{< figure src="/itsi/y3/ex6/images/nobs.png" title="Figure 19: Showing the trusted certificate signed by Let's Encrypt" >}}

---

## References

*For a full bibliography, see the [original BibTeX file](https://github.com/Stefanistkuhl/goobering/blob/master/itsi/y3/ex6/quellen.bib).*

[^1]: This task definition was summarized by ChatGPT using the prompt: "Summarize this task definition in English and LaTeX and make it short and abstract."
[^2]: Docker Documentation. Docker Compose. [source](https://docs.docker.com/compose)
[^3]: Vsupalov. Docker ARG, ENV and .env - a Complete Guide. [source](https://vsupalov.com/docker-arg-env-variable-guide)
[^4]: Apache HTTP Server. htpasswd - Manage user files for basic authentication. [source](https://httpd.apache.org/docs/current/programs/htpasswd.html)
[^5]: man7.org. echo(1) - Linux manual page. [source](https://man7.org/linux/man-pages/man1/echo.1.html)
[^6]: Sling Academy. NGINX location blocks: Understanding and Utilizing URL Matching. [source](https://www.slingacademy.com/article/nginx-location-block-the-complete-guide)
[^7]: Stack Overflow. Getting basic-auth username in php. [source](https://stackoverflow.com/questions/316847/getting-basic-auth-username-in-php)
[^8]: DigitalOcean. How To Create a Self-Signed SSL Certificate for Nginx in Ubuntu 20.04. [source](https://www.digitalocean.com/community/tutorials/how-to-create-a-self-signed-ssl-certificate-for-nginx-in-ubuntu-20-04-1)
[^9]: ShellHacks. HowTo: Create CSR using OpenSSL Without Prompt (Non-Interactive). [source](https://www.shellhacks.com/create-csr-openssl-without-prompt-non-interactive)
[^10]: Wikipedia. List of DNS record types. [source](https://en.wikipedia.org/w/index.php?title=List_of_DNS_record_types&oldid=1260647885)
[^11]: IETF Datatracker. RFC 1035: Domain names - implementation and specification. [source](https://datatracker.ietf.org/doc/html/rfc1035#page-35)
[^12]: Certbot. certbot — Certbot 3.1.0.dev0 documentation. [source](https://eff-certbot.readthedocs.io/en/latest/man/certbot.html)
[^13]: nixCraft. How to forcefully renew Let's Encrypt certificate on Linux or Unix. [source](https://www.cyberciti.biz/faq/how-to-forcefully-renew-lets-encrypt-certificate)


