from .utils import logger, environment

from fabric import Connection

import vagrant
import os
import shutil


def create_runner_directory(folder_name: str, filename: str) -> None:
    os.makedirs(folder_name)

    source_file = os.path.join(
        os.getcwd(), filename
    )  # Assuming file is in current directory
    destination_file = os.path.join(folder_name, filename)

    shutil.copy2(source_file, destination_file)
    logger.info(f"Initialized runner directory {folder_name}")


def start_vm(url: str, registration_token: str, labels: list, workflow_id: int) -> None:
    work_dir = os.path.join(environment.get("VAGRANT_WORK_FOLDER"), str(workflow_id))
    create_runner_directory(work_dir, "Vagrantfile")

    vm = vagrant.Vagrant(root=work_dir)
    vm.up()
    logger.info(f"VM started for {workflow_id}")

    host = vm.user_hostname_port()
    client = Connection(host, connect_kwargs={"key_filename": vm.keyfile()})
    print(client.run("pwd; ls -la"))
