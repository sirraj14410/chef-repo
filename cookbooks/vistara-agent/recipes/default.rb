#
# Cookbook Name :: vistara-agent
# Recipe        :: default
#
# Copyright 2014, VistaraIT, Inc.
#
# All rights reserved - Do Not Redistribute
#

call_home_server = node['agent']['call_home_server']
call_home_port   = node['agent']['call_home_port']
api_key          = node['agent']['api_key']
api_secret       = node['agent']['api_secret']
proxy_type       = node['agent']['proxy']['type']
proxy_server     = node['agent']['proxy']['server']
proxy_port       = node['agent']['proxy']['port']
agent_version    = node['agent']['version']

cookbook_file "/tmp/deployAgent.py"

package_found = "rpm -qa | grep vistara-agent-#{agent_version}"
if platform?("ubuntu", "debian")
	package_found = "dpkg -l | grep vistara-agent | grep #{agent_version}"
end

deploy_command = "python /tmp/deployAgent.py -i silent -K #{api_key} -S #{api_secret} -s #{call_home_server} -p #{call_home_port} -v #{agent_version}"
if proxy_type == 'proxy'
	deploy_command = "python /tmp/deployAgent.py -i silent -K #{api_key} -S #{api_secret} -s #{call_home_server} -p #{call_home_port} -v #{agent_version} -m proxy -H #{proxy_server} -P #{proxy_port}" 
end

execute "run_deploy_agent" do
	command "#{deploy_command}"
	not_if "#{package_found}"				
end

execute "remove_deploy_agent_script" do
	command "rm -f /tmp/deployAgent.py"
	only_if { ::File.exists?("/tmp/deployAgent.py")}
end

