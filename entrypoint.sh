#!/bin/bash
# set -x
DTRACK_URL=$1
DTRACK_KEY=$2
LANGUAGE=$3
DELETE=$4
FAIL_ON_CRITICAL=$5
FAIL_ON_HIGH=$6

INSECURE="--insecure"
#VERBOSE="--verbose"

# Access directory where GitHub will mount the repository code
# $GITHUB_ variables are directly accessible in the script
cd $GITHUB_WORKSPACE

# Run check for delete variable first so that install doesn't need to be run
PROJECT=$(curl -X GET -G --data-urlencode "name=$GITHUB_REPOSITORY"  \
                         --data-urlencode "version=$GITHUB_HEAD_REF" \
                         "$DTRACK_URL/api/v1/project/lookup" -H  "accept: application/json" -H  "X-Api-Key: $DTRACK_KEY")
PROJECT_EXISTS=$(echo $PROJECT | jq ".active" 2>/dev/null)
if [[ -n "$PROJECT_EXISTS" ]]; then
    PROJECT_UUID=$(echo $PROJECT | jq -r ".uuid" 2>/dev/null)
else
    PROJECT_UUID=$(curl \
        -d "{  \"name\": \"$GITHUB_REPOSITORY\",  \"version\": \"$GITHUB_HEAD_REF\"}" \
        -X PUT "$DTRACK_URL/api/v1/project" \
        -H  "accept: application/json" \
        -H  "X-Api-Key: $DTRACK_KEY" | jq -r ".uuid" 2>/dev/null
    )
fi


if [[ $DELETE == "true" ]]; then
    DELETE_CODE=$(curl -X DELETE --head -w "%{http_code}" "$DTRACK_URL/api/v1/project/$PROJECT_UUID" -H  "accept: application/json" -H  "X-Api-Key: $DTRACK_KEY")
    echo "DELETE_CODE is $DELETE_CODE"
    if [[ $DELETE_CODE == "HTTP/2 204" ]]; then
        exit 0
    else
        echo $PROJECT
        echo $PROJECT_EXISTS
        echo $GITHUB_HEAD_REF
        echo $PROJECT_UUID
        exit 1
    fi
fi

case $LANGUAGE in
    "nodejs")
        lscommand=$(ls)
        echo "[*] Processing NodeJS BoM"
        apt-get install --no-install-recommends -y nodejs
        export NVM_DIR="$HOME/.nvm" && (
        git clone https://github.com/nvm-sh/nvm.git "$NVM_DIR"
        cd "$NVM_DIR"
        git checkout `git describe --abbrev=0 --tags --match "v[0-9]*" $(git rev-list --tags --max-count=1)`
        ) && \. "$NVM_DIR/nvm.sh"
        if [[ -f ".nvmrc" ]];
        then
            nvm install
            nvm use
        else
            nvm install 16.14.2
            nvm alias default 16.14.2
            nvm use default
        fi
        npm install
        npm audit fix --force
        if [ ! $? = 0 ]; then
            echo "[-] Error executing npm install. Stopping the action!"
            exit 1
        fi
        npm install -g @cyclonedx/cyclonedx-npm
        path="bom.xml"
        cyclonedx-npm --help
        BoMResult=$(cyclonedx-npm --output-format XML --short-PURLs --output-file bom.xml)
        ;;

    "python")
        echo "[*]  Processing Python BoM"
        apt-get install --no-install-recommends -y python3 python3-pip
        freeze=$(pip freeze > requirements.txt)
        if [ ! $? = 0 ]; then
            echo "[-] Error executing pip freeze to get a requirements.txt with frozen parameters. Stopping the action!"
            exit 1
        fi
        pip install cyclonedx-bom
        path="bom.xml"
        BoMResult=$(cyclonedx-py -o bom.xml)
        ;;

    "golang")
        echo "[*]  Processing Golang BoM"
        if [ ! $? = 0 ]; then
            echo "[-] Error executing go build. Stopping the action!"
            exit 1
        fi
        path="bom.xml"
        BoMResult=$(cyclonedx-go -o bom.xml)
        ;;

    "ruby")
        echo "[*]  Processing Ruby BoM"
        if [ ! $? = 0 ]; then
            echo "[-] Error executing Ruby build. Stopping the action!"
            exit 1
        fi
        apt-get install --no-install-recommends -y build-essential ruby-dev
        gem install cyclonedx-ruby
        path="bom.xml"
        BoMResult=$(cyclonedx-ruby -p ./ -o bom.xml)
        ;;

    "java")
        echo "[*]  Processing Java BoM"
        if [ ! $? = 0 ]; then
            echo "[-] Error executing Java build. Stopping the action!"
            exit 1
        fi
        apt-get install --no-install-recommends -y build-essential default-jdk maven
        path="target/bom.xml"
        BoMResult=$(mvn compile)
        ;;

    "dotnet")
        echo "[*]  Processing Golang BoM"
        if [ ! $? = 0 ]; then
            echo "[-] Error executing NuGet (Dotnet) build. Stopping the action!"
            exit 1
        fi
        path="bom.xml/bom.xml"
        dotnet tool install --global CycloneDX
        apt-get update
        # The path to a .sln, .csproj, .vbproj, or packages.config file or the path to
        # a directory which will be recursively analyzed for packages.config files
        BoMResult=$(dotnet CycloneDX . -o bom.xml)
        ;;

    "php")
        echo "[*]  Processing Php Composer BoM"
        if [ ! $? = 0 ]; then
            echo "[-] Error executing Php build. Stopping the action!"
            exit 1
        fi
        apt-get install --no-install-recommends -y build-essential php php-xml php-mbstring
        curl -sS "https://getcomposer.org/installer" -o composer-setup.php
        php composer-setup.php --install-dir=/usr/bin --version=2.0.14 --filename=composer
        composer require --dev cyclonedx/cyclonedx-php-composer
        path="bom.xml"
        BoMResult=$(composer make-bom --spec-version="1.2")
        ;;

    *)
        "[-] Project type not supported: $LANGUAGE"
        exit 1
        ;;
esac
MAIN_PROJECT=$(curl -X GET -G --data-urlencode "name=$GITHUB_REPOSITORY"  \
                         --data-urlencode "version=refs/heads/main" \
                         "$DTRACK_URL/api/v1/project/lookup" -H  "accept: application/json" -H  "X-Api-Key: $DTRACK_KEY")
MAIN_PROJECT_EXISTS=$(echo $MAIN_PROJECT | jq ".active" 2>/dev/null)
MAIN_PROJECT_UUID=$(echo $MAIN_PROJECT | jq -r ".uuid" 2>/dev/null)


MASTER_PROJECT=$(curl -X GET -G --data-urlencode "name=$GITHUB_REPOSITORY"  \
                         --data-urlencode "version=refs/heads/master" \
                         "$DTRACK_URL/api/v1/project/lookup" -H  "accept: application/json" -H  "X-Api-Key: $DTRACK_KEY")
MASTER_PROJECT_EXISTS=$(echo $MASTER_PROJECT | jq ".active" 2>/dev/null)
MASTER_PROJECT_UUID=$(echo $MASTER_PROJECT | jq -r ".uuid" 2>/dev/null)


if [[ -n "$MAIN_PROJECT_EXISTS" ]]; then
    baseline_project=$(curl  $INSECURE $VERBOSE -s --location --request GET -G "$DTRACK_URL/api/v1/metrics/project/$MAIN_PROJECT_UUID/current" \
--header "X-Api-Key: $DTRACK_KEY")
    baseline_score=$(echo $baseline_project | jq ".inheritedRiskScore")
elif [[ -n "$MASTER_PROJECT_EXISTS" ]]; then
    baseline_project=$(curl  $INSECURE $VERBOSE -s --location --request GET -G "$DTRACK_URL/api/v1/metrics/project/$MASTER_PROJECT_UUID/current" \
--header "X-Api-Key: $DTRACK_KEY")
else
    baseline_project=$(curl  $INSECURE $VERBOSE -s --location --request GET -G "$DTRACK_URL/api/v1/metrics/project/$PROJECT_UUID/current" \
--header "X-Api-Key: $DTRACK_KEY")
fi

baseline_score=$(echo $baseline_project | jq ".inheritedRiskScore" 2>/dev/nulll)

echo "[*] BoM file succesfully generated"

# Cyclonedx CLI conversion
echo "[*] Cyclonedx CLI conversion"

# UPLOAD BoM to Dependency track server
echo "[*] Uploading BoM file to Dependency Track server"
upload_bom=$(curl $INSECURE $VERBOSE -s --location --request POST $DTRACK_URL/api/v1/bom \
--header "X-Api-Key: $DTRACK_KEY" \
--header "Content-Type: multipart/form-data" \
--form "autoCreate=true" \
--form "projectName=$GITHUB_REPOSITORY" \
--form "projectVersion=$GITHUB_HEAD_REF" \
--form "bom=@bom.xml")


token=$(echo $upload_bom | jq ".token" | tr -d "\"")
echo "[*] BoM file succesfully uploaded with token $token"


if [ -z $token ]; then
    echo "[-]  The BoM file has not been successfully processed by OWASP Dependency Track"
    exit 1
fi

echo "[*] Checking BoM processing status"
processing=$(curl $INSECURE $VERBOSE -s --location --request GET $DTRACK_URL/api/v1/bom/token/$token \
--header "X-Api-Key: $DTRACK_KEY" | jq '.processing')


while [ $processing = true ]; do
    sleep 5
    processing=$(curl  $INSECURE $VERBOSE -s --location --request GET $DTRACK_URL/api/v1/bom/token/$token \
--header "X-Api-Key: $DTRACK_KEY" | jq '.processing')
    if [ $((++c)) -eq 50 ]; then
        echo "[-]  Timeout while waiting for processing result. Please check the OWASP Dependency Track status."
        exit 1
    fi
done

echo "[*] OWASP Dependency Track processing completed"

# wait to make sure the score is available, some errors found during tests w/o this wait
sleep 60

echo "[*] Retrieving project information"
project=$(curl  $INSECURE $VERBOSE -s --location --request GET "$DTRACK_URL/api/v1/project/lookup?name=$GITHUB_REPOSITORY&version=$GITHUB_HEAD_REF" \
--header "X-Api-Key: $DTRACK_KEY")

echo "-----PROJECT-------"
echo $project
echo "-------------------------"

if [[ -n "$baseline_score" ]]; then
    echo "Previous score was: $baseline_score"
    echo "baselinescore=$baseline_score" >> $GITHUB_OUTPUT
    previous_critical=$(echo $baseline_project | jq ".critical")
    previous_high=$(echo $baseline_project | jq ".high")
    previous_medium=$(echo $baseline_project | jq ".medium")
    previous_low=$(echo $baseline_project | jq ".low")
    previous_unassigned=$(echo $baseline_project | jq ".unassigned")
fi
project_metrics=$(curl  $INSECURE $VERBOSE -s --location --request GET -G "$DTRACK_URL/api/v1/metrics/project/$PROJECT_UUID/current" \
                    --header "X-Api-Key: $DTRACK_KEY")
project_uuid=$(echo $project | jq ".uuid" | tr -d "\"")
risk_score=$(echo $project | jq ".lastInheritedRiskScore")
critical=$(echo $project_metrics | jq ".critical")
high=$(echo $project_metrics | jq ".high")
medium=$(echo $project_metrics | jq ".medium")
low=$(echo $project_metrics | jq ".low")
unassigned=$(echo $project_metrics | jq ".unassigned")

echo "-----PROJECT METRICS-----"
echo $project_metrics
echo "-------------------------"

echo "riskscore=$risk_score" >> $GITHUB_OUTPUT
echo "critical=$critical" >> $GITHUB_OUTPUT
echo "high=$high" >> $GITHUB_OUTPUT
echo "medium=$medium" >> $GITHUB_OUTPUT
echo "low=$low" >> $GITHUB_OUTPUT
echo "unassigned=$unassigned" >> $GITHUB_OUTPUT
echo "previouscritical=$previous_critical" >> $GITHUB_OUTPUT
echo "previoushigh=$previous_high" >> $GITHUB_OUTPUT
echo "previousmedium=$previous_medium" >> $GITHUB_OUTPUT
echo "previouslow=$previous_low" >> $GITHUB_OUTPUT
echo "previousunassigned=$previous_unassigned" >> $GITHUB_OUTPUT
echo "project_url=$DTRACK_URL/projects/$PROJECT_UUID" >> $GITHUB_OUTPUT
echo "fail_on_critical=$FAIL_ON_CRITICAL" >> $GITHUB_OUTPUT
echo "fail_on_high=$FAIL_ON_HIGH" >> $GITHUB_OUTPUT

cat $GITHUB_OUTPUT
if [[ $critical -gt 0 ]] && [[ $FAIL_ON_CRITICAL == "true" ]];
then
    echo 'Failing due to presence of criticals'
    exit 1
fi

if [[ $high -gt 0 ]] && [[ $FAIL_ON_HIGH == "true" ]];
then
    echo 'Failing due to presence of highs'
    exit 1
fi
