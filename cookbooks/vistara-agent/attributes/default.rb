#
# Cookbook Name :: vistara-agent
# Attributes    :: default
#
# Copyright 2015, VistaraIT, Inc.
#

default['agent'] = {
	"call_home_server" => "api.vistara.io",
	"call_home_port"   => "443",
	"api_key"          => "36fv9ATrCxfz5vP5CfHygXbW5aqPCcvN",
	"api_secret"       => "gmf2k8wUAkccyrsAxVs9QjA5PF3BqRUXQY7v45XU4n86nxdS49XjcDcfnHFXZCFg",
	"version"          => "3.7.0-1",
	"proxy"            => {
    	"type"   => "direct",
    	"server" => "",
    	"port"   => "3128"	
	}
}
