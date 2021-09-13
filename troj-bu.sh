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
				#service throwaway container with 
				# - access from outside via local sshd server
				# - access to local resources (dirs) for backup
        docker image ls --format "{{.Repository}}:{{.Tag}}" | grep -q $IMAGE_BU && return
        echo "    creating image $IMAGE_BU for backup container ($CONT_BU)"
        docker build -t $IMAGE_BU - << DOCKERFILE_END
FROM linuxserver/openssh-server
RUN apk add --no-cache --upgrade rsync gocryptfs
DOCKERFILE_END
}

function log {
        strZ='                                '
				[[ -z $2 ]] && return
        echo "${strZ:0:$1}$2"
}

function bu-local-dir {
     # ARGS:
		 # 1. name of "master" container for which backup is made
		 # 2. JSON object with parameters
      bu_dir="$(echo "$2" | jq -er .bu_dir?)" || bu_dir="$BU_DIR"
      bu_dir="${bu_dir/#\~/$HOME}"/${1}
			[[ -d "$bu_dir" ]] || { mkdir -p "$bu_dir"; }
			echo "$bu_dir"
}

function get_source_dir_spec {
				#ARGS: 
				#1. Mounts object from `docker inspect <container>`
				#2. src_dirs multiline
				vol_spec=''
				for src_dir in $src_dirs; do
						mnt="$(echo $1|jq ".|select (.Destination == \"$src_dir\")")"
						case $(echo ${mnt}|jq -r ".Type") in
						  "volume")
								vol_spec+=" -v $(echo $mnt|jq -r '.Name'):/__bu$(echo $mnt|jq -r '.Destination')"
																;;
							"bind")
								vol_spec+=" -v $(echo $mnt|jq -r '.Source'):/__bu$(echo $mnt|jq -r '.Destination')"
																;;
						esac
				done
				echo "$vol_spec"
}

function rw {
				#get raw value
				echo "$CHK" | jq -r "$1"
}

########################################################################################
function sql-bu {
             # ARGS:
						 # 1. name of "master" container for which backup is done
				     # 2. JSON object with parameters
						 #echo "$2" && return
             bu_cont="$1"
             db_cont=$(echo "$2" | jq -r .container)
             db_name=$(echo "$2" | jq -r .db)
         db_username=$(echo "$2" | jq -r .username)
         db_password=$(echo "$2" | jq -r .password)
				 arch_file=$(bu-local-dir "$1" "$2")_backup.sql.gz
  log 5 "mysqldump| host:$db_cont / database:$db_name"
  
  docker exec "$db_cont" mysqldump -u "$db_username" "-p${db_password}"  ${db_name} \
          |gzip > "$arch_file"  \
          && log 5 "local file recorded:" && log 0 "$(ls -lh $arch_file)"
}

function rsync-bu {
        # ARGS:
				# 1. name of "master" container for which backup is done
				# 2. JSON object with parameters
        create_bu_image

				bu_cont="$1"
				src_dirs="$(echo "$2" | jq -r .src[])"
				bu_local_dir=$(bu-local-dir "$1" "$2") 
				bu_username="monkey"

					local mount_dirs="$(docker inspect ${1}|jq -r '.[].Mounts[]')"

					src_dirs=$(get_source_dir_spec "$mount_dirs" "$src_dirs")
					echo "$IMAGE_BU"
					echo "$src_dirs"


					docker run -d \
									--name=$CONT_BU \
									$src_dirs \
									-e PUID=1001 \
									-e PGID=1001 \
									-e PASSWORD_ACCESS=true \
									-e USER_PASSWORD=boo \
									-e USER_NAME=${bu_username}\
									-e PUBLIC_KEY="$(cat ~/.ssh/id_rsa.pub)" \
									-p 2222:2222 \
									$IMAGE_BU

					echo "got here"
					return

					for src_dir in "${src_dirs}"; do
									rsync --rsh="ssh -p2222 -J ${REMOTE_HOST}"  ${bu_username}@localhost:/${src_dir}  \
													${bu_local_dir}/
					done
}

########################################################################################
#check if docker image for backup container exists on remote host
log  0 "start job for remote host $REMOTE_HOST"


for bu_cont in $(jq -r '.containers|keys[]' "$CONF_FL"); do
				for task_k in $(jq -r ".containers[\"${bu_cont}\"].tasks|keys[]" "$CONF_FL"); do
								#echo "2nd"
								task=$(jq -r ".containers[\"${bu_cont}\"].tasks[$task_k]" "$CONF_FL")
								case $(echo "${task}" | jq -r ".driver") in
												"mysqldump")
																sql-bu "$bu_cont" "$task"
																;;
												"rsync")
																rsync-bu "$bu_cont" "$task"
																;;
								esac
				done
done
