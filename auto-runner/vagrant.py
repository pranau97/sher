from .utils import logger, environment

from fabric import Connection

import vagrant
import os
import shutil
import time


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
    start_time = time.time()
    vm.up()
    end_time = time.time()
    logger.info(f"VM provisioned for {workflow_id} in {end_time - start_time} seconds")

    host = vm.user_hostname_port()
    client = Connection(host, connect_kwargs={"key_filename": vm.keyfile()})

    command = "cd actions-runner && \\"
    command += f"./config.sh --unattended --url {url} \
        --token {registration_token} \
        --labels {','.join(labels)} \
        --name auto-runner-{workflow_id} --ephemeral && \\"
    command += "./run.sh"

    start_time = time.time()
    result = client.run(command, hide=True)
    end_time = time.time()

    if not result.ok:
        logger.error(
            f"Error running command: stderr:\n{result.stderr}\nstdout:\n{result.stdout}"
        )
    else:
        logger.info(
            f"Runner started for {workflow_id} in {end_time - start_time} seconds"
        )


def destroy_vm(workflow_id: int) -> None:
    work_dir = os.path.join(environment.get("VAGRANT_WORK_FOLDER"), str(workflow_id))

    if os.path.exists(work_dir):
        vm = vagrant.Vagrant(root=work_dir)
        vm.destroy()
        logger.info(f"VM destroyed for {workflow_id}")

        if os.path.exists(work_dir):
            shutil.rmtree(work_dir)
            logger.info(f"Folder '{work_dir}' and its contents deleted successfully")
    else:
        logger.warning(f"Folder '{work_dir}' does not exist")
