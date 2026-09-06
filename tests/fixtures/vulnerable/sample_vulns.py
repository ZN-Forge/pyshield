"""Fixture file containing intentional security vulnerabilities for scanner testing."""

import os
import subprocess


def trigger_eval(user_data: str):
    # PS101
    return eval(user_data)


def trigger_exec(code_str: str):
    # PS102
    exec(code_str)


def trigger_os_system(cmd: str):
    # PS103
    os.system(cmd)


def trigger_subprocess(cmd: str):
    # PS104
    subprocess.run(cmd, shell=True)
