# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure("2") do |config|
  # The most common configuration options are documented and commented below.
  # For a complete reference, please see the online documentation at
  # https://docs.vagrantup.com.

  # Every Vagrant development environment requires a box. You can search for
  # boxes at https://vagrantcloud.com/search.
  config.vm.box = "generic/ubuntu2204"
  config.vm.provider "libvirt"
  config.vm.synced_folder ".", "/vagrant", disabled: true
  config.vm.hostname = "runner"

  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y jq
    wget $(curl -s https://api.github.com/repos/actions/runner/releases/latest | \
    jq -r '.assets[] | select(.name | contains ("linux-x64")) | .browser_download_url')
  SHELL
end
