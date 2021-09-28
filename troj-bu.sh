#!/bin/bash

#backup files and database locally by specifying containers, volumes and database

#ARGS:
# - config file. backup-troj.conf by default
# - --restore: "restore" mode ("backup" mode by default)
# - -t|--tag: tags separated by comma to include. default - all tasks
#             Note: tag is attribute of a task
# - -n|--name: container name(s), separated by comma. default - all containers
#LIMITATIONS:
# 1) for rsync driver: mountpoints can be specified as the source
# 2) though in config file more than one task with same driver can be specified,
#    the script will store all data under same local dir (REMOTE_HOST/CONTAINER_NAME/DRIVER)
#    which will make mess on restoration.TODO: replace <driver> with task's tag or key
# 3) at the moment executing `docker run` command makes necessary to re-start script. Hence,
#    one must always run script with -n <container-name> args and backup containers one-by-one.

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
				    -h|--host)
				      REMOTE_HOST="$2"
							shift
							shift ;;
				     --dry-run)
				      DRY_RUN=1
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

#try to determine remote host if not specified in arguments
[[ -z $REMOTE_HOST ]]  \
   && REMOTE_HOST=$(docker context inspect | jq '.[].Endpoints.docker.Host' \
        |sed 's/"//g'|sed 's/^.*\/\///') 

if [[ -z $REMOTE_HOST ]]; then
				log 2 "failed to determine remote host name"
				return
fi

## GLOBAL VARS
BU_DIR=$(jq -r '.conf?.bu_dir?' "$CONF_FL")

IMAGE_BU=troj-bu:local   #name of image for throwaway backup container, name:tag format
CONT_BU=troj-bu
#HARDCODED: root dir where source dirs of interest are mounted is /__bu. 

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

function _bu_local_dir {
     # ARGS:
		 # 1. name of "master" container for which backup is made
		 # 2. JSON object with parameters
		 # returns <config_bu_local_dir>/<host_name>/<container_name>
		  local bu_dir
		  bu_dir="$(jq -er ".containers[\"$1\"].conf?.bu_dir?"  $CONF_FL)" || bu_dir=$BU_DIR
      #extend '~' with home dir path of desktop AT THE BEGINNING of $bu_dir
      bu_dir="${bu_dir/#\~/$HOME}"/${REMOTE_HOST}/${1}
			[[ -d "$bu_dir" ]] || { mkdir -p "$bu_dir"; }
			echo "$bu_dir"
}

function get_source_dir_spec {
				#ARGS: 
				#1. Mounts object from `docker inspect <container>`
				#2. src_dirs multiline, optional. Source mountpoints from config file. 
				#   Acts as filter to avoid picking up mounts, not selected for backup. 
				#   If empty, all mounts are processed
				local src_dirs=${2:-$(echo $1|jq -r '.Destination')}
				local vol_spec=''
				while read src_dir; do
						local mnt="$(echo $1|jq ".|select (.Destination == \"$src_dir\")")"
						#backup destination dirs are "flatenned" to handle sub-mounts cases
						#
						case $(echo ${mnt}|jq -r ".Type") in
						  "volume")
								local source_key='Name'
																;;
							"bind")
								local source_key='Source'
																;;
						esac
						vol_spec+=" -v "$(echo $mnt|jq -r ".${source_key} +\":\"+.Destination")
				done < <(echo "$src_dirs" | sort)

				#trim leading space
				echo "$vol_spec" |sed 's/^[[:space:]]*//'
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
function _mysqldump {
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
	   local bu_local_dir=$(_bu_local_dir "$1" "$2")/mysqldump
		 local bu_local_file="${bu_local_dir}/backup.sql.gz"
		 mkdir -p "$bu_local_dir"
  log 5 "mysqldump, $3| host:$db_cont / database:$db_name"
  
	if [[ $3 == "bu" ]]; then
			ssh ${REMOTE_HOST} docker exec "$db_cont" \
					mysqldump -u "$db_username" "-p${db_password}"  ${db_name} \
					|gzip > "$bu_local_file"  \
					&& log 5 "local file recorded:" && log 0 "$(ls -lh $bu_local_file)"
  else
      #check that user exists in the database
      ssh ${REMOTE_HOST} docker exec "$db_cont" \
							mysql -u $db_username -p"${db_password}" || return
			gunzip -c $bu_local_file | ssh ${REMOTE_HOST} "docker exec -i $db_cont sh -c \"mysql -u $db_username -p${db_password} ${db_name}\" " \
							&& log 5 "database was restored from local file $bu_local_file"
	fi

}

function _rsync {
        # ARGS:
				# 1. name of "master" container for which backup is done
				# 2. JSON object with parameters
				# 3. mode: bu|restore
        create_bu_image
				#remove_bu_container

				local src_dirs_conf="$(echo "$2" | jq -r '.src[]')"
				bu_username="monkey"

				local mount_dirs="$(ssh ${REMOTE_HOST} docker inspect ${1}|jq -r '.[].Mounts[]')"

				#get volume specs for target container in standard command-line form for
				#`docker run`: -v source:destination
				local src_dirs_str=$(get_source_dir_spec "$mount_dirs" "$src_dirs_conf")
				#adjustments:
				# 1) add /__bu root directory to avoid possible overlapping with service
				#    bu containwer own file structure
				# 2) remove subdir in 'destination' part, to handle ovelapping submounts.
				#    Directories separator is hard-coded symbol '.':
				#    /parent-dir/leaf-dir -> /parent-dir.leaf-dir
				local src_dirs_str_cnt=$(echo $src_dirs_str| sed ':a; s|:/\([^ /]\+\)/|:/\1.|g; ta; s|:/|:/__bu/|g')

docker_run_cmd=$(tr '\n' ' ' <<DOCKER_RUN_END
docker run -d 
--name=$CONT_BU  
$src_dirs_str_cnt
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

# check if service bu container exist
local bu_c_status=$(ssh ${REMOTE_HOST} "docker ps -a --filter name=$CONT_BU --format {{.Status}}")
   case $bu_c_status in
			'')
				#container does not exist
				ssh ${REMOTE_HOST} "$docker_run_cmd" \
				&& log 2 "created bu container $CONT_BU" \
				&& log 2 "re-run backup for $1 / rsync task to complete backup" \
				&& return
#For unknown reason ssh command if run after container creation by "docker run"
# usually fails even if delayed for 3-5 sec.
				;;
			*)
			#container exists, perform "mountprint" check

			#get all container's mounts for existing service bu container
			mount_dirs="$(ssh ${REMOTE_HOST} docker inspect ${CONT_BU}|jq -r '.[].Mounts[]')"
			local src_dirs_str_b=$(get_source_dir_spec "$mount_dirs" )
				#

				[[ $src_dirs_str_cnt != $src_dirs_str_b ]]  \
			       && log 3 "existing backup service container did not pass check test:"  \
						 && log 1 "$src_dirs_str_cnt" \
						 && log 1 "$src_dirs_str_b" \
						 && log 3 "Removing existing service container" \
						 && ssh ${REMOTE_HOST} "docker rm -f ${CONT_BU}" \
						 && sleep 5 \
				     && ssh ${REMOTE_HOST} "$docker_run_cmd" \
				     && log 2 "created bu container $CONT_BU" \
				     && log 2 "re-run backup for $1 / rsync task to complete backup" \
				     && return
				[[ $bu_c_status != Up* ]] && ssh ${REMOTE_HOST} "docker start $CONT_BU" \
				&& log 3 "staring existing container $CONT_BU" && sleep 5
				;;
	esac

 local bu_local_dir=$(_bu_local_dir "$1" "$2")/rsync/
 local rsync_args="$(echo "$2" | jq -r '.args?' | sed 's/^null$//') ${DRY_RUN:+--dry-run }" 

 if [[ $3 == 'bu' ]]; then
    log 2 "backup to local dir: $bu_local_dir " 
		rsync --rsh="ssh -p2222 -J ${REMOTE_HOST} ${SSH_LOCAL_CONF}" \
						-avzH --delete $rsync_args "${bu_username}@localhost:/__bu/"  \
						$bu_local_dir
 else
    log 2 "restoration from local dir: $bu_local_dir " 
		rsync --rsh="ssh -p2222 -J ${REMOTE_HOST} ${SSH_LOCAL_CONF}" \
						-avzH --delete  $bu_local_dir/  \
						"${bu_username}@localhost:/__bu/" 
 fi

	return
					for src_dir in $(echo $src_dirs|sed 's/-v/\n/g'|sed '/^ *$/d'|sed 's/.*://'); do
#									echo "!!!>${src_dir}<"

               if [[ $3 == 'bu' ]]; then
                  rsync --rsh="ssh -p2222 -J ${REMOTE_HOST} ${SSH_LOCAL_CONF}" \
													-avzH --delete "${bu_username}@localhost:${src_dir}"  \
													"${bu_local_dir}/" 
				       else
                  rsync --rsh="ssh -p2222 -J ${REMOTE_HOST} ${SSH_LOCAL_CONF}" \
													-avzH --delete  "${bu_local_dir}" \
													"${bu_username}@localhost:${src_dir}" 
							 fi
					done
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
								_mysqldump "$bu_cont" "$task" "bu"
								;;
				 mysqldump-restore)
								 _mysqldump "$bu_cont" "$task" "restore"
								 ;;
				"rsync-bu")
								_rsync "$bu_cont" "$task" "bu"
								;;
				 rsync-restore)
								_rsync "$bu_cont" "$task" "restore"
								;;
			esac
		done
		[[ restart_container -eq 1 ]] &&  log 5 "START CONTAINER $bu_cont" \
						&& docker start $bu_cont >/dev/null && restart_container=0
  done
}

log  0 "start job for remote host $REMOTE_HOST"
main
