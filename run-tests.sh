#!/bin/bash

PYTHON="${PYTHON:-python3.12}"

set -e

OAREPO_VERSION="${OAREPO_VERSION:-12}"

clean_up(){
  set +e
  # Kill Kerberos and other Docker services
  docker stop kerberos-kdc
  docker rm kerberos-kdc
  docker compose down

  # Remove Kerberos ticket
  kdestroy
}

if [ "$0" = "$BASH_SOURCE" ]; then
  trap "clean_up" EXIT
fi


build_dataset(){
  (
  BUILDER_VENV=.venv-builder
  if test -d $BUILDER_VENV ; then
    rm -rf $BUILDER_VENV
  fi

  $PYTHON -m venv $BUILDER_VENV
  . $BUILDER_VENV/bin/activate
  pip install -U setuptools pip wheel
  pip install -U oarepo-model-builder


  if test -d datasets ; then
    rm -rf datasets
  fi

  oarepo-compile-model ./tests/datasets.yml --output-directory datasets
)
}

start_docker_services(){
  echo "Starting Docker services..."
  docker compose up -d
  sleep 10
}

setup_local_kdc(){
  (
  echo "Setting up Kerberos KDC..."
  cd setup_local_kdc
  docker build -t custom-kerberos-kdc .

  # Run the Kerberos KDC container
  docker run -d --name kerberos-kdc -p 2222:88 -p 2223:464 custom-kerberos-kdc

  # Wait for Kerberos to initializeAn
  sleep 5

  # Configure Kerberos principals and keytab
  echo -e "userpassword\nuserpassword" | docker exec -i kerberos-kdc kadmin.local -q "addprinc admin/admin@EXAMPLE.COM"
  echo -e "userpassword\nuserpassword" | docker exec -i kerberos-kdc kadmin.local -q "addprinc user@EXAMPLE.COM"
  docker exec kerberos-kdc kadmin.local -q "addprinc -randkey HTTP/localhost@EXAMPLE.COM"
  docker exec kerberos-kdc kadmin.local -q "ktadd -k /etc/krb5kdc/flask.keytab HTTP/localhost@EXAMPLE.COM"
  )

  # Copy the keytab to the host
  docker cp kerberos-kdc:/etc/krb5kdc/flask.keytab ./tests/flask.keytab
}


get_ticket(){
  echo "Authenticating Kerberos user..."
  export KRB5_CONFIG=./setup_local_kdc/krb5-client.conf
  kinit user@EXAMPLE.COM <<< "userpassword"
}

export VENV=".venv"

setup_test_venv(){
(
  if test -d $VENV ; then
    rm -rf $VENV
  fi

  $PYTHON -m venv $VENV
  . $VENV/bin/activate
  pip install -U setuptools pip wheel

  pip install "oarepo[tests]==${OAREPO_VERSION}.*"
  pip install -e ".[tests]"
  pip install pytest-invenio
  pip install -e datasets
)
}

run_tests(){
  . $VENV/bin/activate
  export KRB5_CONFIG=./setup_local_kdc/krb5-client.conf
  echo "Running tests..."
  pytest tests
}

if [ "$0" = "$BASH_SOURCE" ]; then
    build_dataset
    start_docker_services
    setup_local_kdc
    get_ticket
    setup_test_venv
    run_tests
else
    echo "This script includes the following functions:"
    echo "1. build_dataset: builds model"
    echo "2. start_docker_services: Starts Docker containers (DB, Cache etc.)"
    echo "3. setup_local_kdc: Configures a local Kerberos Key Distribution Center (KDC) for authentication."
    echo "4. get_ticket: Obtains a Kerberos ticket for authentication testing."
    echo "5. setup_test_venv: Sets up a virtual environment for testing."
    echo "6. run_tests: Runs pytest."
    echo ""
    echo "To execute the script, run it directly: ./run-tests.sh"
fi






