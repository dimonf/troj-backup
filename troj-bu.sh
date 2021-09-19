#!/bin/bash

#backup files and database locally by specifying containers, volumes and database

#ARGS:
# - config file. backup-troj.conf by default
# - --restore: "restore" mode ("backup" mode by default)
# - -t|--tag: tags separated by comma to include. default - all tasks
#             Note: tag is attribute of a task
# - -n|--name: container name(s), separated by comma. default - all containers

bu_mode="bu"
while [[ $# -gt 0 ]]; do
				key="$1"
				case "$key" in
    				--restore)
							bu_mode="restore"
							shift ;;
				    -t|--tags)
				      TAGS="$2"
							shift
							shift ;;
				    -n|--names)
				      CONTAINERS="$2"
							shift
							shift ;;
	      		 *)
							config_file="$key"
							shift ;;
        esac
done

#assumptions:
# - mysql container: tar is installed
# - on local PC installed: jq
# - conf file structure (json):
#{
#  "conf": {
#    "bu_dir": "~/usb-hd/plain/bu"
#  },
#  "containers": {
#    "piwigo": {
#      "conf": {
#        "bu_dir": "~/tmp"
#      },
#      "tasks": [
#        {
#          "driver": "mysqldump",
#          "container": "sql-server",
#          "db": "piwigo-db",
#          "username": "piwigo-username",
#          "password": "piwigo-password"
#        },
#        {
#          "driver": "rsync",
#          "src": [
#            "/gallery",
#            "/config"
#          ]
#        }
#      ]
#    },
#    "another_cont" :{
#        ...
#      }
#  }
#}
CONF_FL=${config_file:-backup-troj.conf}
SSH_LOCAL_CONF="-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=ERROR"

REMOTE_HOST=$(docker context inspect | jq '.[].Endpoints.docker.Host' \
        |sed 's/"//g'|sed 's/^.*\/\///') 
REMOTE_HOST=bird.lan

## GLOBAL VARS
BU_DIR=$(jq -r '.conf?.bu_dir?' "$CONF_FL")

IMAGE_BU=troj-bu:local   #name of image for throwaway backup container, name:tag format
CONT_BU=troj-bu

function create_bu_image {
				#service throwaway container with 
				# - access from outside via local sshd server
				# - access to local resources (dirs) for backup
        ssh ${REMOTE_HOST} docker image ls --format "{{.Repository}}:{{.Tag}}" \
								| grep -q $IMAGE_BU && return
        echo "    creating image $IMAGE_BU for backup container ($CONT_BU)"
        ssh ${REMOTE_HOST} docker build -t $IMAGE_BU - << DOCKERFILE_END
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
		  bu_dir="$(jq -er ".containers[\"$1\"].conf?.bu_dir?"  $CONF_FL)" || bu_dir=$BU_DIR
#      bu_dir="$(echo "$2" | jq -er .bu_dir?)" || bu_dir="$BU_DIR"
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

function remove_bu_container {
		if ssh ${REMOTE_HOST} docker ps -a  | grep $CONT_BU -q; then
				log 5 "removing existing container $CONT_BU"
		    ssh ${REMOTE_HOST} docker rm -f "$CONT_BU" 1>/dev/null
		fi
}


function check_container_is_on {
		docker ps -a --format "{{json .}}"| jq -r ".|select(.Names == \"$CONT_BU\").Status?" \
						|grep -iq '^Up'
		ssh 
}
########################################################################################
function mysqldump {
             # ARGS:
						 # 1. name of "master" container for which backup is done
				     # 2. JSON object with parameters
						 # 3. mode: bu|restore
						 #echo "$2" && return
       local bu_cont="$1"
       local db_cont=$(echo "$2" | jq -r .container)
       local db_name=$(echo "$2" | jq -r .db)
   local db_username=$(echo "$2" | jq -r .username)
   local db_password=$(echo "$2" | jq -r .password)
     local arch_file=$(bu-local-dir "$1" "$2")_backup.sql.gz
  log 5 "mysqldump, $3| host:$db_cont / database:$db_name"
  
	if [[ $3 == "bu" ]]; then
			ssh ${REMOTE_HOST} docker exec "$db_cont" \
					mysqldump -u "$db_username" "-p${db_password}"  ${db_name} \
					|gzip > "$arch_file"  \
					&& log 5 "local file recorded:" && log 0 "$(ls -lh $arch_file)"
  else
      #check that user exists in the database
      ssh ${REMOTE_HOST} docker exec "$db_cont" \
							mysql -u $db_username -p"${db_password}" || return
			gunzip -c $arch_file | ssh ${REMOTE_HOST} "docker exec -i $db_cont sh -c \"mysql -u $db_username -p${db_password} ${db_name}\" " \
							&& log 5 "database was restored from local file $arch_file"
	fi

}

function rsync {
        # ARGS:
				# 1. name of "master" container for which backup is done
				# 2. JSON object with parameters
				# 3. mode: bu|restore
        create_bu_image
				#remove_bu_container

				bu_cont="$1"
				src_dirs="$(echo "$2" | jq -r .src[])"
				bu_local_dir=$(bu-local-dir "$1" "$2") 
				bu_username="monkey"

					local mount_dirs="$(ssh ${REMOTE_HOST} docker inspect ${1}|jq -r '.[].Mounts[]')"

					src_dirs=$(get_source_dir_spec "$mount_dirs" "$src_dirs")
					#echo "$IMAGE_BU"
					#echo "$src_dirs"

docker_cmd=$(tr '\n' ' ' <<DOCKER_RUN_END
docker run -d 
--name=$CONT_BU 
$src_dirs 
-e PUID=1001 
-e PGID=1001 
-e PASSWORD_ACCESS=false
-e USER_PASSWORD=boo 
-e USER_NAME=${bu_username}
-e PUBLIC_KEY="$(cat ~/.ssh/id_rsa.pub)" 
-p 2222:2222 
$IMAGE_BU  
DOCKER_RUN_END
)

                  ! { ssh ${REMOTE_HOST} docker ps | grep $CONT_BU -q; } \
									&& ssh ${REMOTE_HOST}  "$docker_cmd" \
									&& log 2 "created bu container $CONT_BU" \
									&& log 2 "re-run backup script  for $bu_cont / rsync task to complete backup" \
									&& return
#For unknown reason ssh command if run after container creation by "docker run"
# usually fails even if delayed for 3-5 sec.

					for src_dir in $(echo $src_dirs|sed 's/-v/\n/g'|sed '/^ *$/d'|sed 's/.*://'); do
#									echo "!!!>${src_dir}<"

               if [[ $3 == 'bu' ]]; then
                  rsync --rsh="ssh -p2222 -J ${REMOTE_HOST} ${SSH_LOCAL_CONF}" \
													-avzH --delete "${bu_username}@localhost:${src_dir}"  \
													"${bu_local_dir}/" 
				       else
											 echo 'here'
							 fi
					done
}


function rsync-restore {
     echo 'boo'
}

########################################################################################


function main {
  #apply filter by container name
	#https://stackoverflow.com/questions/29518137/jq-selecting-a-subset-of-keys-from-an-object
#	local bu_conts="$(jq -r --args keys $(echo $CONTAINERS|jq -R 'split(",")') \
#					'.containers|with_entries(select(
#						.key as $k| any($keys |fromjson[]; .==$k)))' "$CONF_FL")"
  
  for bu_cont in $(jq -r '.containers|keys[]' "$CONF_FL"); do
    #FILTER: --name
		[[ -n "$CONTAINERS" && ! "$CONTAINERS" =~ (^|,)$bu_cont(,|$) ]] && continue
    #stop container if required
		local restart_container=0
		jq -er ".containers[\"${bu_cont}\"].conf?|select(.stop_before_bu==true)" "$CONF_FL">/dev/null \
						&& log 5 "STOP CONTAINER $bu_cont" \
						&& docker stop $bu_cont >/dev/null  \
						&& restart_container=1

		for task_k in $(jq -r ".containers[\"${bu_cont}\"].tasks|keys[]" "$CONF_FL"); do
			task=$(jq -r ".containers[\"${bu_cont}\"].tasks[$task_k]" "$CONF_FL")
			echo "$task" | jq -e '.skip?==true' >/dev/null && continue
      #FILTER: --tags
			local bu_tag=$(echo "$task" | jq -er '.tag?')  && \
			[[ -n $bu_tag && -n "$TAGS" && ! "$TAGS" =~ (^|,)$bu_tag(,|$) ]] \
					 && continue

			task_f="$(echo "$task" | jq -r ".driver")-$bu_mode"

			case $task_f in
				"mysqldump-bu")
								mysqldump "$bu_cont" "$task" "bu"
								;;
				 mysqldump-restore)
								 mysqldump "$bu_cont" "$task" "restore"
								 ;;
				"rsync-bu")
								rsync "$bu_cont" "$task" "bu"
								;;
				 rsync-restore)
								rsync "$bu_cont" "$task" "restore"
								;;
			esac
		done
		[[ restart_container -eq 1 ]] &&  log 5 "START CONTAINER $bu_cont" \
						&& docker start $bu_cont >/dev/null && restart_container=0
  done
}

log  0 "start job for remote host $REMOTE_HOST"
main
