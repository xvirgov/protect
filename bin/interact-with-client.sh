#!/bin/bash -e

# user must have appropriate permissions to work with the specified secret

error() {
  echo "Incorrect arguments specified"
  echo "Use -h for help"
  exit 1
}

eval_input() {
  if [ -z "$1" ]; then
    error
  fi
}

eval_action() {
  ACTION=$1
  INPUT_FILE=$2
  OUTPUT_FILE=$3

  # action can be only enc, dec or gen
  if [[ $ACTION != "gen" && $ACTION != "enc" && $ACTION != "dec" ]]; then
    error
  fi

  # if enc or dec, files must be specified and input file must exist
  if [[ $ACTION == "enc" || $ACTION == "dec" ]]; then
    eval_input $INPUT_FILE
    eval_input $OUTPUT_FILE

    if [[ ! -f "$INPUT_FILE" ]]; then
      echo "Input file does not exist!"
      exit 1
    fi
  fi
}

usage() {
  echo "Usage:"
  echo "    -h                    display help message"
  echo "    -c [rsa|ecies|kyber]  cipher"
  echo "    -a [gen|enc|dec]      action"
  echo "    -s [name]             secret"
  echo "    -i [name]             input file"
  echo "    -o [name]             output file"
  echo "Mandatory input parameters: -c, -a, -s, [-i and -o, if enc or dec action]"
}

# Parse the arguments
while getopts ":hc:a:s:i:o:" opt; do
  case ${opt} in
  h)
    usage
    exit 0
    ;;
  c)
    CIPHER=$OPTARG
    ;;
  a)
    ACTION=$OPTARG
    ;;
  s)
    SECRET=$OPTARG
    ;;
  i)
    INPUT_FILE=$OPTARG
    ;;
  o)
    OUTPUT_FILE=$OPTARG
    ;;
  \?)
    error
    ;;
  esac
done

# Check parameters
eval_input "$CIPHER"
eval_input "$ACTION"
eval_input "$SECRET"
eval_action "$ACTION" "$INPUT_FILE" "$OUTPUT_FILE"

# Set REST parameters
[[ $ACTION == "enc" ]] && REST_ACTION="encrypt"
[[ $ACTION == "dec" ]] && REST_ACTION="decrypt"

[[ $CIPHER == "rsa" ]] && REST_CIPHER="proactive-rsa"
[[ $CIPHER == "ecies" ]] && REST_CIPHER="ecies"
[[ $CIPHER == "kyber" ]] && REST_CIPHER="kyber"

# Perform the rest request

if [[ $ACTION == "gen" ]]
then
  if [[ $CIPHER == "rsa" || $CIPHER == "kyber" ]]
  then
    # rsa, kyber - honest dealer
    curl -k --cacert conf-tmp/ca/ca-key-clients.pem \
    --cert conf-tmp/client/certs/cert-administrator \
    --key conf-tmp/client/keys/private-administrator \
    "https://localhost:8080/generate-keys?cipher=${REST_CIPHER}&secretName=${SECRET}"
  else
    # ecies - dkg
    curl -k --cacert conf-tmp/ca/ca-key-clients.pem \
    --cert conf-tmp/client/certs/cert-administrator \
    --key conf-tmp/client/keys/private-administrator \
    "https://localhost:8081/generate?secretName=${SECRET}"
  fi

  exit $?
fi

# enc/dec
curl -k --data-binary "@$INPUT_FILE" \
  --max-time 20 \
  --cacert conf-tmp/ca/ca-key-clients.pem \
  --cert conf-tmp/client/certs/cert-administrator \
  --key conf-tmp/client/keys/private-administrator \
  "https://localhost:8080/${REST_ACTION}?cipher=${REST_CIPHER}&secretName=${SECRET}" \
  --output "$OUTPUT_FILE"
