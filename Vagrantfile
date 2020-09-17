# frozen_string_literal: true

# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure('2') do |config|
  config.vm.define :node1 do |node|
    node.vm.box = 'centos/7'
    node.vm.network :private_network, ip: '192.168.33.11'
  end

  config.vm.define :node2 do |node|
    node.vm.box = 'centos/7'
    node.vm.network :private_network, ip: '192.168.33.12'
  end
end
