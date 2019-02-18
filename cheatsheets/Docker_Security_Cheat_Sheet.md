# Introduction

Docker containers are the most popular containerisation technology. Used properly can increase level of security (in comparison to running application directly on the host). On the other hand some misconfigurations can lead to downgrade level of security or even introduce new vulnerabilities.

The aim of this cheat sheet is to provide an easy to use list of common security mistakes and good practices that will help you securing your Docker containers.

# Rules

## RULE \#0 - Keep Host and Docker up to date

todo:  

## RULE \#1 - Do not expose the Docker socket (even to the containers)

todo:

## RULE \#2 - Set filesystem and volumes to read-only 

todo:

## RULE \#3 - Set a USER or enable user namespace support (--userns-remap=default) 

todo:


## RULE \#4 - Limit capabilities (Grant only specific capabilities, needed by a container)

todo: 

Do not run containers with the privileged flag!!!

## RULE \#5 - Disable inter-container communication (--icc=false)

## RULE \#6 - Use security profiles (seccomp, AppArmor, or SELinux)

todo:

Do not disable security profile!!! https://docs.docker.com/engine/security/seccomp/


## RULE \#7 - Limit resources (memory, CPU, file descriptors, processes, restarts)

## RULE \#8 - Add –no-new-privileges flag

# Bonus Rules

## BONUS RULE \#1 - Use IDS like Falco 

## BONUS RULE \#2 - Protect your provate Docker registy 

## BONUS RULE \#3 - Delete sensible data 

## BONUS RULE \#4 - secrets management 

## BONUS RULE \#5 - sandbox like gVisor 

## BONUS RULE \#6 - tools

## BONUS RULE \#7 - distroless images

# Authors and Primary Editors

Jakub Maćkowski - jakub.mackowski@owasp.org
