#!/usr/bin/env bash
set -eu -o pipefail

# If SAFETY_ACTION isn't set, just run safety directly and pass through any commands.
if [ "${SAFETY_ACTION:-}" != "true" ]; then
    export SAFETY_OS_TYPE="docker"
    export SAFETY_OS_RELEASE=""
    export SAFETY_OS_DESCRIPTION="run"

    exec python -m safety $@
fi

find_best_docker_image () {
    for image_id in $(docker images --filter "dangling=false" --format="{{.ID}}"); do
        json=$(docker inspect $image_id)

        safety_autodetect_ignore=$(echo "${json}" | jq -r .[0].Config.Labels.safety_autodetect)

        created_at=$(date --date="$(echo "${json}" | jq -r .[0].Created)" +%s)
        now=$(date +%s)

        # Skip the action itself
        if [[ "${safety_autodetect_ignore}" == "ignore" ]]; then
            continue
        fi

        # Limit of 1 hour to scan back
        if [[ "$(($now-$created_at))" -gt 3600 ]]; then
            break
        fi

        echo $image_id
        break
    done
}

get_repo_tags () {
    docker inspect "${1}" | jq -r "(.[0].RepoTags // [\"${1}\"]) | join(\",\")"
}

export SAFETY_OS_TYPE="docker action"
export SAFETY_OS_RELEASE=""
export SAFETY_OS_DESCRIPTION=""

# auto / docker / env / file
if [ "${SAFETY_ACTION_SCAN}" = "auto" ]; then
    echo "[Safety Action] Autodetecting Mode..." 1>&2
    SAFETY_OS_DESCRIPTION="${SAFETY_OS_DESCRIPTION} mode_auto"

    if [ "$(find_best_docker_image)" != "" ]; then
        SAFETY_ACTION_SCAN="docker"
        SAFETY_OS_DESCRIPTION="${SAFETY_OS_DESCRIPTION} docker_detected"
        echo "[Safety Action] Autodetected mode: docker - Safety will scan a recently built Docker container. If this is not what you want, set the scan variable in the action configuration manually." 1>&2
    elif [ "${pythonLocation:-}" != "" ]; then
        SAFETY_ACTION_SCAN="env"
        SAFETY_OS_DESCRIPTION="${SAFETY_OS_DESCRIPTION} env_detected"
        echo "[Safety Action] Autodetected mode: env - Safety will scan the Action CI environment. If this is not what you want, set the scan variable in the action configuration manually." 1>&2
    elif [ -e "Pipfile.lock" ] || [ -e "poetry.lock" ] || [ -e "requirements.txt" ]; then
        SAFETY_ACTION_SCAN="file"
        SAFETY_OS_DESCRIPTION="${SAFETY_OS_DESCRIPTION} file_detected"
        echo "[Safety Action] Autodetected mode: file - Safety will scan a lock file commited in this repo. If this is not what you want, set the scan variable in the action configuration manually." 1>&2
    else
        echo "[Safety Action] Could not autodetect mode. Please set the scan variable in the action configuration manually." 1>&2
        exit 1
    fi
fi

# remediation mode
if [ "${SAFETY_ACTION_CREATE_PR}" = "true" ]; then
    if [ "${SAFETY_ACTION_SCAN}" != "file" ]; then
        echo "[Safety Action] Creating PRs is only supported when scanning a requirements file."
        exit 1
    fi

    # TODO: Add info to env vars for telemetry...

    # Build up a list of requirements files, or use SAFETY_ACTION_REQUIREMENTS if that's set.
    # This will be moved into Safety proper in the future.
    requirement_files=()
    if [ -z "${SAFETY_ACTION_REQUIREMENTS}" ]; then
        readarray -d '' matches < <(find . -type f -name requirements.txt -print0)
        for match in ${matches[@]}; do
            requirement_files+=("-r" "${match}")
        done
    else
        requirement_files=("-r" "${SAFETY_ACTION_REQUIREMENTS}")
    fi

    # Continue on error is set because we're using Safety's output here for further processing.
    python -m safety check "${requirement_files[@]}" --continue-on-error --output=json ${SAFETY_ACTION_ARGS} | python -m safety alert github-pr --repo "${GITHUB_REPOSITORY}" --token "${GITHUB_TOKEN}" --base-url "${GITHUB_API_URL}"

    exit 0
fi

if [ "${SAFETY_ACTION_SCAN}" = "docker" ]; then
    if [[ "${SAFETY_ACTION_DOCKER_IMAGE}" == "" ]]; then
        SAFETY_OS_DESCRIPTION="${SAFETY_OS_DESCRIPTION} docker_image_scan"

        SAFETY_ACTION_DOCKER_IMAGE="$(find_best_docker_image)"
        SAFETY_ACTION_DOCKER_IMAGE_FRIENDLY="$(get_repo_tags "${SAFETY_ACTION_DOCKER_IMAGE}")"
    else
        SAFETY_OS_DESCRIPTION="${SAFETY_OS_DESCRIPTION} docker_image_specified"

        SAFETY_ACTION_DOCKER_IMAGE_FRIENDLY="${SAFETY_ACTION_DOCKER_IMAGE}"
    fi

    echo "[Safety Action] Scanning Docker Image: ${SAFETY_ACTION_DOCKER_IMAGE_FRIENDLY}" 1>&2
    docker run --rm --entrypoint /bin/sh "${SAFETY_ACTION_DOCKER_IMAGE}" -c "python -m pip list --format=freeze" > /tmp/requirements.txt
    SAFETY_ACTION_REQUIREMENTS="/tmp/requirements.txt"
elif [ "${SAFETY_ACTION_SCAN}" = "env" ]; then
    echo "[Safety Action] Scanning Current Environment" 1>&2

    # We're running inside an isolated container, but we have access to the Docker socket.
    # Run a command, in the root NS, to pip freeze and send that through for scanning.
    # Somewhat based on the idea at https://gist.github.com/BretFisher/5e1a0c7bcca4c735e716abf62afad389
    # Use pip list --format=freeze instead of pip freeze due to things like
    # https://stackoverflow.com/questions/64194634/why-pip-freeze-returns-some-gibberish-instead-of-package-version
    if [ "${pythonLocation:-}" != "" ]; then
        SAFETY_OS_DESCRIPTION="${SAFETY_OS_DESCRIPTION} env_pythonLocation"

        docker run --rm --privileged --pid=host justincormack/nsenter1 "${pythonLocation}/bin/python" -m pip list --format=freeze > /tmp/requirements.txt
    else
        SAFETY_OS_DESCRIPTION="${SAFETY_OS_DESCRIPTION} env_root"

        docker run --rm --privileged --pid=host justincormack/nsenter1 /bin/sh -c "pip list --format=freeze" > /tmp/requirements.txt
    fi
    SAFETY_ACTION_REQUIREMENTS="/tmp/requirements.txt"
elif [ "${SAFETY_ACTION_SCAN}" = "file" ]; then
    if [[ "${SAFETY_ACTION_REQUIREMENTS}" == "" ]]; then
        SAFETY_OS_DESCRIPTION="${SAFETY_OS_DESCRIPTION} file_path_scan"

        if [ -e "poetry.lock" ]; then
            SAFETY_OS_DESCRIPTION="${SAFETY_OS_DESCRIPTION} file_path_scan_poetry"
            SAFETY_ACTION_REQUIREMENTS="$(pwd)/poetry.lock"
        elif [ -e "Pipfile.lock" ]; then
            SAFETY_OS_DESCRIPTION="${SAFETY_OS_DESCRIPTION} file_path_scan_pipfile"
            SAFETY_ACTION_REQUIREMENTS="$(pwd)/Pipfile.lock"
        elif [ -e "requirements.txt" ]; then
            SAFETY_OS_DESCRIPTION="${SAFETY_OS_DESCRIPTION} file_path_scan_requirementstxt"
            SAFETY_ACTION_REQUIREMENTS="$(pwd)/requirements.txt"
        else
            echo "[Safety Action] Could not autodetect a poetry.lock / Pipfile.lock / requirements.txt automatically. Try set the requirements variables in the action configuration." 1>&2
            exit 1
        fi

        echo "[Safety Action] Autodetecting Requirements File: ${SAFETY_ACTION_REQUIREMENTS}" 1>&2
    else
        SAFETY_OS_DESCRIPTION="${SAFETY_OS_DESCRIPTION} file_path_specified"
    fi

    echo "[Safety Action] Scanning Requirements File: ${SAFETY_ACTION_REQUIREMENTS}" 1>&2

    if [[ "$(basename ${SAFETY_ACTION_REQUIREMENTS})" == "Pipfile.lock" ]]; then
        SAFETY_OS_DESCRIPTION="${SAFETY_OS_DESCRIPTION} file_pipfile_converted"

        cd "$(dirname ${SAFETY_ACTION_REQUIREMENTS})"
        pipenv requirements > /tmp/requirements.txt
        echo "[Safety Action] Converted ${SAFETY_ACTION_REQUIREMENTS} to /tmp/requirements.txt using pipenv." 1>&2
        SAFETY_ACTION_REQUIREMENTS="/tmp/requirements.txt"
    elif [[ $(basename ${SAFETY_ACTION_REQUIREMENTS}) == "poetry.lock" ]]; then
        SAFETY_OS_DESCRIPTION="${SAFETY_OS_DESCRIPTION} file_poetry_converted"

        cd "$(dirname ${SAFETY_ACTION_REQUIREMENTS})"
        poetry export -f requirements.txt --without-hashes > /tmp/requirements.txt
        echo "[Safety Action] Converted ${SAFETY_ACTION_REQUIREMENTS} to /tmp/requirements.txt using poetry." 1>&2
        SAFETY_ACTION_REQUIREMENTS="/tmp/requirements.txt"
    fi

    if [[ "${SAFETY_ACTION_CONTINUE_ON_ERROR,,}" == "yes" || "${SAFETY_ACTION_CONTINUE_ON_ERROR,,}" == "true" ]]; then
        SAFETY_ACTION_CONTINUE_ON_ERROR="--continue-on-error"
    fi
fi

if [[ "${SAFETY_API_KEY:-}" == "" ]]; then
    echo "[Safety Action] An API key is required to use this action. Please sign up for an account at https://pyup.io/" 1>&2
    exit 1
fi

# Don't hard fail from here on out; so we can return the exit code and output
set +e

# This sends the output to both stdout and our variable, without buffering like echo would.
exec 5>&1
output=$(python -m safety check -r "${SAFETY_ACTION_REQUIREMENTS}" --output="${SAFETY_ACTION_OUTPUT_FORMAT}" ${SAFETY_ACTION_CONTINUE_ON_ERROR} ${SAFETY_ACTION_ARGS} | tee >(cat - >&5))
exit_code=$?

# https://github.community/t/set-output-truncates-multiline-strings/16852/3
output="${output//'%'/'%25'}"
output="${output//$'\n'/'%0A'}"
output="${output//$'\r'/'%0D'}"

echo "::set-output name=exit-code::$exit_code"
echo "::set-output name=cli-output::$output"

exit $exit_code
