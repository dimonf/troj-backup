#!/bin/bash

#backup files and database locally by specifying containers, volumes and database

#ARGS:
# - config file. backup-troj.conf by default


#assumptions:
# - mysql container: tar is installed
# - on local PC installed: jq
# - conf file structure (json):
#   {
#     "conf": {
#         "bu_dir":"</path/to/bu/dir>
#      }
#     "containers":  [ 
#            {"container": <container name>,
#            "bu_dir": </path/to/bu/dir> #overrides bu_dir of global level
#            "rsync":{
#                   "src": [
#                          "/path/to/files",
#                    ]
#             }
#            "mysqldump":{
#                   "src": [
#                          {
#                              "container": <DB container name>,
#                              "db":        <DB name>,
#                              "username":  <username>,
#                             "password":  <password>
#                          }
#                    ]
#                }
#            },
#            {....}
#   ]
#}

CONF_FL=${1:-backup-troj.conf}

REMOTE_HOST=$(docker context inspect | jq '.[].Endpoints.docker.Host' \
        |sed 's/"//g'|sed 's/^.*\/\///') 

## GLOBAL VARS
BU_DIR=$(jq -r '.conf?.bu_dir?' "$CONF_FL")

IMAGE_BU=bu-troj:local   #name of image for throwaway backup container, name:tag format
CONT_BU=bu-troj

function create_bu_image {
        docker image ls --format "{{.Repository}}:{{.Tag}}" | grep -q $IMAGE_BU && return
        echo "    creating image $IMAGE_BU for backup container ($CONT_BU)"
        docker build -t $IMAGE_BU - << DOCKERFILE_END
FROM linuxserver/openssh-server
RUN apk add --no-cache --upgrade rsync gocryptfs
DOCKERFILE_END
}

function log {
        strZ='                                '
        echo "${strZ:0:$1}$2"
}
########################################################################################
#check if docker image for backup container exists on remote host
echo "  start job for remote container $REMOTE_HOST"
create_bu_image

#backup mysql databases
for P in $(jq -r '.containers[].container' "$CONF_FL" ); do
  CHK=$(jq ".containers[]|select(.container == \"$P\").mysqldump?.src[0]?" "$CONF_FL")
  [ 'null' = "$CHK" ] && continue

             db_cont=$(echo "$CHK" | jq -r .container)
             db_name=$(echo "$CHK" | jq -r .db)
         db_username=$(echo "$CHK" | jq -r .username)
         db_password=$(echo "$CHK" | jq -r .password)
              bu_dir="$(echo "$CHK" | jq -er .bu_dir?)" || bu_dir="$BU_DIR"
              bu_dir="${bu_dir/#\~/$HOME}"
           arch_file="${bu_dir}/${P}_backup.sql.gz"
  mkdir -p "$bu_dir"
  log 5 "mysqldump| host:$db_cont / database:$db_name"
  
  docker exec "$db_cont" mysqldump -u "$db_username" "-p${db_password}"  ${db_name} \
          |gzip > "$arch_file" \
          && log 5 "local file recorded:" && log 0 "$(ls -lh $arch_file)"
done
