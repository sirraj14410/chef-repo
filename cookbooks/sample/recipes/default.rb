# Cookbook Name:: sample
# Recipe:: default
#
# Copyright 2015, YOUR_COMPANY_NAME
#
# All rights reserved - Do Not Redistribute
#
#directory "/tmp/nani" do
 # owner 'root'
  #group 'root'
#  mode '0755'
 # action :create
#end
#package "tar" do
 # version "1.16.1"
  #action :install
#end
#template '/tmp/somefile' do
 # mode 00644
  #source 'somefile.erb'
   # only_if do
    #File.exists?('/etc/passwd')
#  end
#end
#template '/tmp/somefile' do
 # mode 00644
  #source 'somefile.erb'
  #not_if {File.exists?('/etc/passwd')}
#end
#template '/tmp/somefile' do
 # mode 00644
  #source 'somefile.erb'
  #only_if 'test -f /etc/passwd'
#end
user 'random' do
  supports :manage_home => true
  comment 'Random User'
  uid 1234
  gid 'users
  home '/home/random'
  shell '/bin/bash'
  password '$nnn'
end
