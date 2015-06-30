#!/usr/bin/env python
'''
/*
 * This computer program is the confidential information and proprietary trade
 * secret of VistaraIT, Inc. Possessions and use of this program must  conform
 * strictly to the license agreement between the user and VistaraIT, Inc., and
 * receipt or possession does not convey any rights to divulge, reproduce,  or
 * allow others to use this program without specific written authorization  of
 * VistaraIT, Inc.
 * 
 * Copyright (c) 2014 VistaraIT, Inc. All rights reserved.
 */
'''

import os, sys, platform, commands, urllib2
from optparse import OptionParser, OptionGroup
if sys.version_info < (2, 4):
    print "Python is an old version that is not supported. Update Python to Version 2.4.* or later and start the agent again."
    sys.exit(1)

installType   = 'interactive'
agent_version = 'AGENT_VERSION'

server        = 'NCARE_SERVER'
port          = 'NCARE_PORT'
api_server    = 'API_SERVER'
api_port      = 'API_PORT'
api_key       = 'API_KEY'
api_secret    = 'API_SECRET'

agentProxy    = 'PROXY_TYPE'
proxy_server  = 'PROXY_SERVER'
proxy_port    = 'PROXY_PORT'
proxy_user    = None
proxy_passwd  = None
proxy_port    = proxy_port.replace("PROXY_PORT", "3128")


usage = "Use the proper command line arguments. \nUsage: %prog [-i silent] [-K key] [-S secret] [-s server] [-p port] [-v agent-version] [-m proxy -H proxy-server -P proxy-port] [-U proxy-user -A proxy-password]\n"
parser = OptionParser(usage=usage)
group = OptionGroup(parser, 'Optional parameters')
group.add_option("-K", "--key", dest="key", default="", help="Oauth API key authorization.")
group.add_option("-S", "--secret", dest="secret", default="", help="Oauth API secret.")
group.add_option("-v", "--agentversion", dest="agentversion", default="", help="Agent version that needs to be installed")
group.add_option("-s", "--server", dest="server", default="", help="Cloud server to connect. Example: ncare.netenrich.net")
group.add_option("-p", "--port", dest="port", default="", help="Cloud server port to connect. Default: 443")
group.add_option("-m", "--connection-mode", dest="connection", default="", help="The mode of connection - [direct] or gateway.")
group.add_option("-i", "--installtype", dest="installtype", default="", help="Install type - [interactive] or silent")
group.add_option("-H", "--proxy-server", dest="proxyserver", default="", help="Proxy Server IP address")
group.add_option("-P", "--proxy-port", dest="proxyport", default="", help="Proxy Server port. Default: 3128")
group.add_option("-U", "--proxy-user", dest="proxyuser", default="", help="Proxy Server user for authentication")
group.add_option("-A", "--proxy-passwd", dest="proxypasswd", default="", help="Proxy user password")

parser.add_option_group(group)
(options, _args) = parser.parse_args()

if options.key != "":
    api_key = options.key

if options.secret != "":
    api_secret = options.secret
    
if options.agentversion != "":
    agent_version = options.agentversion

if options.server != "":
    server = options.server
    api_server = options.server

if options.port != "":
    port = options.port
    api_port = options.port

if options.connection != "":
    agentProxy = options.connection
    
if options.installtype != "":
    installType = options.installtype

if options.proxyserver != "":
    proxy_server = options.proxyserver

if options.proxyport != "":
    proxy_port = options.proxyport
    
if options.proxyuser != "":
    proxy_user = options.proxyuser
    
if options.proxypasswd != "":
    proxy_passwd = options.proxypasswd
    
if proxy_user:
    if not proxy_passwd:
        print "Password is required for proxy authentication"
        sys.exit(1)

# if proxy_server not in ['', 'PROXY_SERVER']:
#     if proxy_user:
#         proxy_url = "http://%s:%s@%s:%s" % (proxy_user, proxy_passwd, proxy_server, proxy_port)
#     else:
#         proxy_url = "http://%s:%s" % (proxy_server, proxy_port)
#     os.environ['http_proxy'] = proxy_url
#     os.environ['https_proxy'] = proxy_url


if installType != 'silent':
    print """
Hello there! Happy to note that you have decided to install the Vistara Agent on this 
server. Linux Vistara agent will greatly enhance your ability to remotely access this 
server, monitor and manage it.  Please note that the Vistara agent install may require 
the download and install of other dependent packages. This will cause no side-effects. 

Enter 'y' to download packages and continue the install.
Enter 'n' to exit."""
    
    c = sys.stdin.read(1)
    if c != 'y' and c != 'Y':
        sys.exit(1)

agent_url  = "https://s3.amazonaws.com/vg-agent/"
#agent_url  = "https://dl.dropbox.com/u/8561338/"
ubuntu_pkg = "vistara-agent_" + agent_version + "_all.deb"
centos_pkg = "vistara-agent-" + agent_version + "%s.noarch.rpm"
os.environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

def executeCommand(cmd, args=[], ignoreOnError=True):
    for arg in args:
        cmd = cmd + ' ' + str(arg)

    try:
        result = commands.getstatusoutput(cmd)
    except Exception, errmsg:
        return 1, 'Exception caught - ' + str(errmsg)

    if result[0] != 0 and ignoreOnError == False:
        raise Exception("Failed to execute command: " + cmd)
    return result[0] >> 8 , result[1]

def is_exe(fpath):
    return os.path.exists(fpath) and os.access(fpath, os.X_OK)

def isCmdExists(program):
    try:
        fpath, fname = os.path.split(program)
        if fpath:
            return is_exe(program)
        else:
            for path in os.environ["PATH"].split(os.pathsep):
                exe_file = os.path.join(path, program)
                if is_exe(exe_file):
                    return True
        return False
    except:
        return False

def get_arch():
    try:
        arch = executeCommand("uname -m")[1].strip()
        result = {"pentium": "i386",
                "i86pc": "i386",
                "x86_64": "amd64"}.get(arch)
        if result:
            arch = result
        elif (arch[0] == "i" and arch.endswith("86")):
            arch = "i386"
        return arch
    except:
        return ''
    
def getOSInfo():
    os_name = os_release = os_version = python_version = os_distro = ""
    try:
        curPF = sys.platform
        if curPF == 'linux2':
            if isCmdExists("lsb_release"):
                os_name = executeCommand("lsb_release -ds")[1].strip().strip("\"")
                os_version = executeCommand("lsb_release -rs")[1].strip()
                os_distro = executeCommand("lsb_release -is")[1].strip()
            else:
                if sys.version_info < (2, 6):
                    platformInfo = platform.dist()
                    os_name = platformInfo[0].strip("'").capitalize()
                    os_release = platformInfo[2].strip("'").capitalize()
                else:
                    platformInfo = platform.linux_distribution()
                    os_name = platformInfo[0].strip("'")
                    os_release = platformInfo[2].strip("'")
                os_version = platformInfo[1].strip("'")
                os_name = os_name + " " + os_version + " " + os_release
                os_distro = platform.dist()[0].strip("'").lower()
                
                osFile = ''
                if os.path.exists('/etc/redhat-release'):
                    osFile = '/etc/redhat-release'
                elif os.path.exists('/etc/fedora-release'):
                    osFile = '/etc/fedora-release'
                    os_distro = 'fedora'
                elif os.path.exists('/etc/oracle-release'):
                    osFile = '/etc/oracle-release'
                    os_distro = 'oracleserver'
                elif os.path.exists('/etc/system-release'):
                    osFile = '/etc/system-release'
                    os_distro = 'amazonami'
                elif os.path.exists('/etc/SuSE-release'):
                    osFile = '/etc/SuSE-release'
                    os_distro = 'sles'

                if osFile != '':
                    osFd = open(osFile, 'r')
                    os_name = osFd.readline().strip()
                    osFd.close()
                    if 'opensuse' in os_name.lower():
                        os_distro = 'suse'

                if os_distro == 'amazonami':
                    os_version = os_name.split()[-1]
                    #matchObj = re.match(".+release (\d+\.\d+)", os_name)
                    #if matchObj:
                    #    os_version = matchObj.group(1)

        elif curPF == 'darwin':
            os_distro = 'darwin'
            if isCmdExists('sw_vers'):
                os_name = executeCommand("sw_vers -productName")[1].strip().strip("\"")
                os_version = executeCommand("sw_vers -productVersion")[1].strip().strip("\"")
            else:
                os_version = platform.mac_ver()[0]
                os_name = "Mac OS X"
            os_name = os_name + " " + os_version

        python_version = platform.python_version()
        return [os_name, os_version, os_distro, python_version]
    except:
        return [os_name, os_version, os_distro, python_version]

def checkPlatform():
    try:
        os_info = getOSInfo()
        os_distro = os_info[2]
        if isCmdExists("lsb_release"):
            if os_distro == "Ubuntu":
                os_distro = "ubuntu"
            elif os_distro == "Debian":
                os_distro = "debian"
            elif os_distro ==  "CentOS":
                os_distro = "centos"
            elif os_distro ==  "Fedora":
                os_distro = "fedora"
            elif os_distro in ["RedHatEnterprise", "RedHatEnterpriseServer"]:
                os_distro = "redhat"
            elif os_distro == "openSUSE project":
                os_distro = "suse"
            elif os_distro == "SUSE LINUX":
                os_distro = 'sles'
                if 'opensuse' in os_info[0].lower():
                    os_distro = "suse"
            elif os_distro ==  "OracleServer":
                os_distro = "oracleserver"
            elif os_distro ==  "EnterpriseEnterpriseServer" and os.path.exists("/etc/oracle-release"):
                os_distro = "oracleserver"
            elif os_distro ==  "AmazonAMI":
                os_distro = "amazonami"
            elif os_distro ==  "OpenEnterpriseServer":
                os_distro = "oes"
            else:
                os_distro = "unknown"
            return os_distro
        return os_distro
    except:
        return "unknown"

def downloadFile(posturl, dest):
    try:
        if proxy_server not in ['', 'PROXY_SERVER']:
            if proxy_user:
                proxy_url = "http://%s:%s@%s:%s" % (proxy_user,proxy_passwd,proxy_server,proxy_port)
            else:
                proxy_url = "http://%s:%s" % (proxy_server,proxy_port)
            
            proxy_handler = urllib2.ProxyHandler({'http': proxy_url, 'https': proxy_url})
            opener = urllib2.build_opener(proxy_handler)
            urllib2.install_opener(opener)
            
        u = urllib2.urlopen(posturl)
        f = open(dest, 'wb')

        block_sz = 8192
        while True:
            buffer = u.read(block_sz)
            if not buffer:
                break
            f.write(buffer)

        f.close()
        u.close()
        return True
    except urllib2.HTTPError, e:
        print "Unable to download file - %s, Error: %s" % (dest, str(e))
        if os.path.exists("/usr/bin/curl"):
            print "Downloading file - %s using curl" % (dest)
            if executeCommand("curl %s -o %s" %(posturl, dest))[0] == 0:
                print "File - %s has been successfully downloaded using curl" % (dest)
                return True
        return False
    except urllib2.URLError, e:
        print "downloadFile: URL Error Exception - " + str(e.reason)
        return False

try:
    distro = checkPlatform()
    pythonVer = platform.python_version()
    device_arch = get_arch()
    if device_arch not in ['i386', 'amd64']:
        print "Unsupported architecture %s." % (device_arch)
        sys.exit(1)

    cmd = url = pkg = pkgChkCmd = pkgInstCmd = pkgUninstCmd = ""
    print "Detected %s (%s).." % (distro, device_arch)
    if distro in ["ubuntu", "debian"]:
        if executeCommand("dpkg -l | grep vistara-agent >/dev/null")[0] == 0:
            print "Vistara agent is already installed. Hence exiting.."
            sys.exit(1)

        if executeCommand("dpkg -l | grep python-twisted-web >/dev/null")[0] != 0:
            resCode = executeCommand("apt-get -y install python-twisted-web >/dev/null")[0]
            if resCode != 0:
                print "Failed to install python-twisted-web debian package. Hence exiting.."
                sys.exit(2)
            else:
                print "Successfully installed agent dependency package 'python-twisted-web'"

        if executeCommand("dpkg -l | grep python-apt >/dev/null")[0] != 0:
            print "Initiating installation of missing dependency package 'python-apt'"
            if executeCommand("apt-get -y install python-apt >/dev/null")[0] != 0:
                print "Failed to install python-apt debian package. Hence exiting.."
                sys.exit(2)
            else:
                print "Successfully installed agent dependency package 'python-apt'"

        pkgInstCmd = "dpkg -i --force-confnew "
        pkgChkCmd = "dpkg -l | grep vistara-agent"
        pkgUninstCmd = "dpkg -P vistara-agent; rm -rf /opt/vistara >/dev/null"
        pkg = ubuntu_pkg
        url = agent_url + pkg
    elif distro in ["centos", "redhat", "rhel", "fedora", "oracleserver", "amazonami", "suse", "sles"]:
        if executeCommand("rpm -qa | grep vistara-agent >/dev/null")[0] == 0:
            print "Vistara agent is already installed. Hence exiting.."
            sys.exit(1)

        os_release = ""
        osVer = getOSInfo()[1]
        if distro not in ["suse", "sles"]:
            osNum = ''
            if distro in ["centos", "redhat", "rhel", "oracleserver"]:
                if osVer.startswith("5"):
                    osNum = '5'

                    ''' For 5.x release '''
                    if executeCommand("rpm -qa | grep python-sqlite2 >/dev/null")[0] != 0:
                        print "Initiating installation of missing dependency package 'python-sqlite2'"
                        if executeCommand("yum install python-sqlite2 -y")[0] != 0:
                            print "Failed to install 'python-sqlite2' rpm package. Hence exiting.."
                            sys.exit(2)
                        else:
                            print "Successfully installed agent dependency package 'python-sqlite2'"
        
                    if executeCommand("rpm -qa | grep python-ctypes >/dev/null")[0] != 0:
                        print "Initiating installation of missing dependency package 'python-ctypes'"
                        if executeCommand("yum install python-ctypes -y")[0] != 0:
                            print "Failed to install 'python-ctypes' rpm package. Hence exiting.."
                            sys.exit(2)
                        else:
                            print "Successfully installed agent dependency package 'python-ctypes'"
                    ''' End 5.x release dependencies '''
                elif osVer.startswith("6"):
                    osNum = '6'
                elif osVer.startswith("7"):
                    osNum = '7'
                os_release = ".el" + osNum
            elif distro == "amazonami":
                os_release = ".amzn1"
            elif distro == "fedora":
                try:
                    majorVer = osVer.split(".")
                    if int(majorVer) < 17:
                        print "Unsupported Fedora version " + osVer
                        sys.exit(2)
                except:
                    pass
            
            if executeCommand("rpm -qa | grep ^dmidecode >/dev/null")[0] != 0:
                print "Initiating installation of missing dependency package 'dmidecode'"
                resCode = executeCommand("yum install dmidecode -y")[0]
                if resCode != 0:
                    print "Failed to install 'dmidecode' rpm package. Hence exiting.."
                    sys.exit(2)
                else:
                    print "Successfully installed agent dependency package 'dmidecode'"

            if executeCommand("rpm -qa | grep ^pyOpenSSL >/dev/null")[0] != 0:
                print "Initiating installation of missing dependency package 'pyOpenSSL'"
                resCode = executeCommand("yum install pyOpenSSL -y")[0]
                if resCode != 0:
                    print "Failed to install 'pyOpenSSL' rpm package. Hence exiting.."
                    sys.exit(2)
                else:
                    print "Successfully installed agent dependency package 'pyOpenSSL'"

            if executeCommand("rpm -qa | grep yum >/dev/null")[0] != 0:
                if executeCommand("yum install yum -y >/dev/null")[0] != 0:
                    print "Failed to install 'yum' rpm package. Hence exiting.."
                    sys.exit(2)
                else:
                    print "Successfully installed agent dependency package 'yum'"

            coreRes = executeCommand("rpm -qa | grep python-twisted-core >/dev/null")[0]
            webRes = executeCommand("rpm -qa | grep python-twisted-web >/dev/null")[0]
            if (coreRes != 0 and webRes != 0) and osNum == '5':
                print "Initiating installation of missing dependency package 'python-twisted-core/python-twisted-web'"
                rf_cmd = "rpm -qa | grep rpmforge-release >/dev/null"
                resCode = executeCommand(rf_cmd)[0]
                if resCode != 0:
                    print "Unable to find the python-twisted package(s) in the base repo. So installing the rpmforge repo"
                    #repo_base_url = "http://packages.sw.be/rpmforge-release/"
                    repo_base_url = "http://pkgs.repoforge.org/rpmforge-release/"
                    if executeCommand("uname -m 2>/dev/null")[1].strip() == "x86_64":
                        repo_pkg = "rpmforge-release-0.5.3-1.el5.rf.x86_64.rpm"
                    else:
                        repo_pkg = "rpmforge-release-0.5.3-1.el5.rf.i386.rpm"

                    repo_url = repo_base_url + repo_pkg
                    dStatus = downloadFile(repo_url, "/tmp/" + repo_pkg)
                    if dStatus:
                        cmd = "rpm -Uvh /tmp/" + repo_pkg
                        if executeCommand(cmd)[0] != 0:
                            print "Failed to install 'rpmforge-release' rpm package. Hence exiting.."
                            os.remove("/tmp/" + repo_pkg)
                            sys.exit(2)
                        else:
                            print "Successfully installed rpmforge repo package."
                            os.remove("/tmp/" + repo_pkg)
                    else:
                        print "Failed to download the rpmforge repo rpm. Hence exiting.."
                        sys.exit(2)
    
            if coreRes != 0:
                twisted_cmd = "yum install python-twisted-core -y >/dev/null"
                resCode = executeCommand(twisted_cmd)[0]
                if resCode != 0:
                    print "Failed to install python-twisted-core rpm package. Hence exiting.."
                    sys.exit(2)
                else:
                    print "Successfully installed agent dependency package 'python-twisted-core'"
    
            if webRes != 0:
                twisted_cmd = "yum install python-twisted-web -y >/dev/null"
                resCode = executeCommand(twisted_cmd)[0]
                if resCode != 0:
                    print "Failed to install python-twisted-web rpm package. Hence exiting.."
                    sys.exit(2)
                else:
                    print "Successfully installed agent dependency package 'python-twisted-web'"

            versionHash = {}
            coreVer = False
            webVer = False
            cmd = "rpm -qa --queryformat '%{NAME}#%{VERSION}\n' | grep python-twisted-core | awk -F# '{print $2}'"
            version = executeCommand(cmd)[1].strip().split("-")[0]
            if version != "":
                versionHash['python-twisted-core'] = version
                verArr = version.split(".")
                try:
                    if int(verArr[0]) > 8:
                        coreVer = True
                    elif int(verArr[0]) == 8 and int(verArr[1]) >= 2:
                        coreVer = True
                except Exception, emsg:
                    print 'python-twisted-core version check failed - ', emsg
            
            cmd = "rpm -qa --queryformat '%{NAME}#%{VERSION}\n' | grep python-twisted-web | awk -F# '{print $2}'"
            version = executeCommand(cmd)[1].strip().split("-")[0]
            if version != "":
                versionHash['python-twisted-web'] = version
                verArr = version.split(".")
                try:
                    if int(verArr[0]) > 8:
                        webVer = True
                    elif int(verArr[0]) == 8 and int(verArr[1]) >= 2:
                        webVer = True
                except Exception, emsg:
                    print 'python-twisted-web version check failed - ', emsg
    
            if not coreVer or not webVer:
                print "The versions of python-twisted-core and python-twisted-web should be greater than 8.2"
                print "  python-twisted-core >= 8.2, current version - %s" % versionHash.get('python-twisted-core', 0)
                print "  python-twisted-web  >= 8.2, current version - %s" % versionHash.get('python-twisted-web', 0)
                sys.exit(2)
        else:
            if distro == 'sles' and osVer.startswith("11"):
                os_release = ".sles11"
                if executeCommand("rpm -qa | grep ^python-dmidecode >/dev/null")[0] != 0:
                    print "Initiating installation of missing dependency package 'python-dmidecode'"
                    resCode = executeCommand("zypper -n install python-dmidecode")[0]
                    if resCode != 0:
                        print "Failed to install 'python-dmidecode' rpm package. Hence exiting.."
                        sys.exit(2)
                    else:
                        print "Successfully installed agent dependency package 'python-dmidecode'"

                if executeCommand("rpm -qa | grep ^python-openssl >/dev/null")[0] != 0:
                    print "Initiating installation of missing dependency package 'python-openssl'"
                    resCode = executeCommand("zypper -n install python-openssl")[0]
                    if resCode != 0:
                        print "Failed to install 'python-openssl' rpm package. Hence exiting.."
                        sys.exit(2)
                    else:
                        print "Successfully installed agent dependency package 'python-openssl'"
                
                twistedRes = executeCommand("rpm -qa | grep ^python-twisted >/dev/null")[0]
                if twistedRes != 0:
                    twisted_cmd = "zypper -n install python-twisted"
                    resCode = executeCommand(twisted_cmd)[0]
                    if resCode != 0:
                        print "Failed to install python-twisted rpm package. Hence exiting.."
                        sys.exit(2)
                    else:
                        print "Successfully installed agent dependency package 'python-twisted'"
                
                twistedWeb = executeCommand("rpm -qa | grep ^python-twisted-web >/dev/null")[0]
                if twistedWeb != 0:
                    twisted_cmd = "zypper -n install python-twisted-web"
                    resCode = executeCommand(twisted_cmd)[0]
                    if resCode != 0:
                        print "Failed to install python-twisted-web rpm package. Hence exiting.."
                        sys.exit(2)
                    else:
                        print "Successfully installed agent dependency package 'python-twisted-web'"


                versionHash = {}
                coreVer = False
                webVer = False
                cmd = "rpm -qa --queryformat '%{NAME}#%{VERSION}\n' | grep ^python-twisted# | awk -F# '{print $2}'"
                version = executeCommand(cmd)[1].strip().split("-")[0]
                if version != "":
                    versionHash['python-twisted'] = version
                    verArr = version.split(".")
                    try:
                        if int(verArr[0]) > 8:
                            coreVer = True
                        elif int(verArr[0]) == 8 and int(verArr[1]) >= 0:
                            coreVer = True
                    except Exception, emsg:
                        print 'python-twisted version check failed - ', emsg
                
                cmd = "rpm -qa --queryformat '%{NAME}#%{VERSION}\n' | grep python-twisted-web | awk -F# '{print $2}'"
                version = executeCommand(cmd)[1].strip().split("-")[0]
                if version != "":
                    versionHash['python-twisted-web'] = version
                    verArr = version.split(".")
                    try:
                        if int(verArr[0]) > 8:
                            webVer = True
                        elif int(verArr[0]) == 8 and int(verArr[1]) >= 0:
                            webVer = True
                    except Exception, emsg:
                        print 'python-twisted-web version check failed - ', emsg
        
                if not coreVer or not webVer:
                    print "The versions of python-twisted-core and python-twisted-web should be greater than 8.0"
                    print "  python-twisted >= 8.0, current version - %s" % versionHash.get('python-twisted', 0)
                    print "  python-twisted-web  >= 8.0, current version - %s" % versionHash.get('python-twisted-web', 0)
                    sys.exit(2)
            else:
                print "Unsupported SUSE version " + osVer
                sys.exit(2)

        pkgInstCmd = "rpm -Uvh "
        pkgChkCmd = "rpm -qa | grep vistara-agent"
        pkgUninstCmd = "rpm -e vistara-agent; rm -rf /opt/vistara >/dev/null"
        pkg = centos_pkg % (os_release)
        url = agent_url + pkg
    else:
        print "Unsupported OS distro " + distro
        sys.exit(2)

    status = False
    if os.path.exists("/tmp/" + pkg):
        print "The package " + pkg + " is already downloaded."
        status = True
    else:
        print "Downloading the agent package " + pkg
        status = downloadFile(url, "/tmp/" + pkg)
    
    if executeCommand(pkgChkCmd)[0] == 0:
        executeCommand(pkgUninstCmd)

    if status:
        print "Successfully downloaded the vistara agent package"
        pkgInstCmd += "/tmp/" + pkg
        instRes = executeCommand(pkgInstCmd)
        if instRes[0] == 0:
            executeCommand("service vistara-shield stop >/dev/null")
            executeCommand("service vistara-agent stop >/dev/null")
            
            cmd = "python /opt/vistara/agent/bin/configure.py -K %s -S %s -s %s -p %s" % (api_key, api_secret, api_server, api_port)
            if agentProxy.lower() in ["gateway", "nsg", "proxy"]:
                cmd = "python /opt/vistara/agent/bin/configure.py -K %s -S %s -s %s -p %s -m proxy -x %s -r %s" % (api_key, api_secret, api_server, api_port, proxy_server, proxy_port)
                if proxy_user and proxy_passwd:
                    cmd += " -u %s -a %s" % (proxy_user, proxy_passwd)
            updateConf = executeCommand(cmd)
            if updateConf[0] == 0:
                print "Update configuration properties successfully."
            else:
                print "Failed to update the configuration properties."
                sys.exit(2)

            startRes = executeCommand("service vistara-shield start")
            if startRes[0] != 0:
                print "Failed to start the vistara-shield service. " + str(startRes[1])
                sys.exit(2)

            startRes = executeCommand("service vistara-agent start")
            if startRes[0] == 0:
                print "Started vistara-agent service successfully"
                executeCommand("rm -f /tmp/" + pkg)
            else:
                print "Failed to start the vistara-agent service. " + str(startRes[1])
                sys.exit(2)
        else:
            print "Failed to install the vistara-agent. " + str(instRes[1])
            sys.exit(2)
    else:
        print "Failed to download the vistara-agent file."
        sys.exit(2)
except Exception, emsg:
    print "Exception in deployAgent: %s" % (emsg)
    sys.exit(2)
