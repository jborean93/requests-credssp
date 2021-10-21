#!/bin/bash


lib::setup::windows_requirements() {
    echo "Installing Windows pre-requisites"

    export CREDSSP_SERVER=localhost
    export CREDSSP_USERNAME=credsspuser
    export CREDSSP_PASSWORD=Password123

    powershell.exe -NoLogo -NoProfile \
        -File ./build_helpers/win-setup.ps1 \
        -UserName "${CREDSSP_USERNAME}" \
        -Password "${CREDSSP_PASSWORD}" \
        -InformationAction Continue
}

lib::setup::system_requirements() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Installing System Requirements"
    fi

    if [ -f /etc/debian_version ]; then
        echo "No requirements required for Linux"

    elif [ "$(expr substr $(uname -s) 1 5)" == "MINGW" ]; then
        lib::setup::windows_requirements

    else
        echo "Distro not found!"
        false
    fi

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::setup::python_requirements() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Installing Python Requirements"
    fi

    echo "Upgrading baseline packages"
    python -m pip install --upgrade pip setuptools wheel

    echo "Installing requests-credssp"
    python -m pip install .

    echo "Install test requirements"
    python -m pip install -r requirements-test.txt

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::sanity::run() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Running Sanity Checks"
    fi

    python -m pycodestyle \
        requests_credssp \
        --verbose \
        --show-source \
        --statistics

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::tests::run() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Running Tests"
    fi

    python -m pytest \
        --verbose \
        --junitxml junit/test-results.xml \
        --cov requests_credssp \
        --cov-report xml \
        --cov-report term-missing

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}
