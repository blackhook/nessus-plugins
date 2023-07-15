#TRUSTED 56bddaa41cca532ed307a82b812ed9bffaea9f4dfc657f7253b11a630a7d100e9a49ea634461788276cb776d49aa2a80bc3af374299480b1f5af8a0abed905a5919527551963e28f272dfc87b497614fcca1492898f737f7d42a9d5dd9e98bd41ca3b4718bf894bbd3951856b683fdf121d247395f38fa65236fbb7c166640ebda7094e5c009ce6878e06b732c3d1d5340dc6f747e2e86a742370ef218b54e479d59a06dd2d8548746c056eb2daa51c3f6fecf7f6ca4089b39a05ef6a96e434829f619996f609985ce4e95dd94494fcabc8cc01170e9452789bcf8283c62d7279725e3200791e9e9e7929c4794db90aeaec06858f5490faab870775786e2b68e9ec93bcc8ef11582a12f54779f818ec70c2b837fe25be1b1c361f85013bc58c3a0fa8eb67a392e3bcc24dec6ab28cb358c9273aeb9fcd188dde486aa3792bbc2859dcff49222a2c122a27ed124b1ebbf807400c753184cce7f662ac4b61bdcea4ec502845b3dd50a0f45645073da1f6213f8045e399d97034879f12b16464b95fb9d62ac52a84b44f5f34647fe02ca022c4e8a930fbc6e3e06fd719d9e5d0f3b494dc2b3ce0d2ec2f06692af26107657cf9880bb79b11623a49caa3eac00ccfbabed4012a9733209f093ae652cfa8ef8e67f01c8d93fd85c3fa5065fc80e7027098c74261c1ec81aa2ec284aa8cbfdfc6e36692016064e7c7a9b5975a1d4cc05
#
# This script was written by Javier Fernandez-Sanguino
# based on a script written by Renaud Deraison <deraison@cvs.nessus.org>
# with contributions by Gareth M Phillips <gareth@sensepost.com> (additional logins and passwords)
#
# GPLv2
#
# TODO:
# - dump the device configuration to the knowledge base (requires
#   'enable' access being possible)
# - store the CISCO IOS release in the KB so that other plugins (in the Registered
#   feed) could use the functions in cisco_func.inc to determine if the system is
#   vulnerable as is currently done through SNMP (all the CSCXXXX.nasl stuff)
# - store the user/password combination in the KB and have another plugin test
#   for common combinations that lead to 'enable' mode.
#
# Changes by Tenable:
# - Coding changes regarding Cisco IOS XR/XE, along with some minor
#   tweaks in description block, were done (2017/01/13).

include("compat.inc");

if (description)
{
  script_id(23938);
  script_version("1.49");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-1999-0508");

  script_name(english:"Cisco Device Default Password");
  script_summary(english:"Checks for a default password.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device has a default factory password set.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco router has a default password set. A remote,
unauthenticated attacker can exploit this to gain administrative
access.");
  script_set_attribute(attribute:"solution", value:
"Change the Cisco device default password via the command 'enable secret'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:TF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-0508");
  script_set_attribute(attribute:"cvss_score_rationale", value:"AV:N is justified since the plugin tries to login via SSH or Telnet. While the NVD score implies the the device is only accessible locally, that's not explicitly specified in the CVE description: An account on a router, firewall, or other network device has a default, null, blank, or missing password. It is a reasonable assumption that if the plugin can log in with one of the sets of credentials attempted in the plugin, it can own the device (hence CIA complete instead of partial).");
  script_set_attribute(attribute:"vuln_publication_date", value:"1999/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2006-2022 Javier Fernandez-Sanguino and Renaud Deraison");

  script_dependencies("find_service2.nasl", "ssh_get_info.nasl");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("telnet_func.inc");
include("misc_func.inc");
include("ssh_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

global_var ssh_port, telnet_checked, telnet_port, ssh_found, telnet_found;
global_var cisco_pw_report_ssh, cisco_pw_report_telnet;
cisco_pw_report_ssh = "";
cisco_pw_report_telnet = "";

cisco_pw_report = "";
ssh_found = FALSE;
telnet_found = FALSE;

# Function to connect to a Cisco system through telnet, send
# a password

function check_cisco_telnet(login, password, port)
{
 local_var msg, r, r2, soc, report, pass_only;
 local_var i, info, line, ver;

 pass_only = TRUE;
 soc = open_sock_tcp(port);
 if ( ! soc )
 	{
	  telnet_port = 0;
	  return(0);
	}
 msg = telnet_negotiate(socket:soc, pattern:"(ogin:|asscode:|assword:)");
 if(strlen(msg))
 {
  # The Cisco device might be using an AAA access model
  # or have configured users:
  if ( stridx(msg, "sername:") != -1 || stridx(msg, "ogin:") != -1  )  {
    send(socket:soc, data:login + '\r\n');
    msg=recv_until(socket:soc, pattern:"(assword:|asscode:)");
    pass_only = FALSE;
  }

  # Device can answer back with {P,p}assword or {P,p}asscode
  # if we don't get it then fail and close
  if ( strlen(msg) == 0 || (stridx(msg, "assword:") == -1 && stridx(msg, "asscode:") == -1)  )  {
    close(soc);
    return(0);
  }

  send(socket:soc, data:password + '\r\n');
  r = recv(socket:soc, length:4096);

  # TODO: could check for Cisco's prompt here, it is typically
  # the device name followed by '>'
  # But the actual regexp is quite complex, from Net-Telnet-Cisco:
  #  '/(?m:^[\r\b]?[\w.-]+\s?(?:\(config[^\)]*\))?\s?[\$\#>]\s?(?:\(enable\))?\s*$)/')

  # Send a 'show ver', most users (regardless of privilege level)
  # should be able to do this
  send(socket:soc, data:'show ver\r\n');
  r = recv_until(socket:soc, pattern:"(Cisco (Internetwork Operating System|IOS|Adaptive Security Appliance) Software|assword:|asscode:|ogin:|% Bad password|% Login invalid)");
  # TODO: This is probably not generic enough. Some Cisco devices don't
  # use IOS but CatOS for example

  # TODO: It might want to change the report so it tells which user / passwords
  # have been found
  if (
     strlen(r) &&
     (
       "Cisco Internetwork Operating System Software" >< r ||
       "Cisco IOS Software" >< r ||
       "Cisco IOS XR Software" >< r ||
       "Cisco IOS XE Software" >< r ||
       "Cisco Adaptive Security Appliance Software" >< r
     )
  )
  {
    r2 = recv_until(socket:soc, pattern:'^System image file is "[^"]+"');
    if (strlen(r2)) r = strstr(r, "Cisco") + chomp(r2) + '\n' + '(truncated)';

    ver = egrep(pattern:"^.*IOS.*Version [0-9.]+(?:\(.*\))?.*", string:r);
    if (ver) {
        if ( !get_kb_item("Host/Cisco/show_ver" ) )
  		set_kb_item(name:"Host/Cisco/show_ver", value:ereg_replace(string:ver, pattern:".*(Cisco.*)", replace:"\1"));
	info = '\n  ' + chomp(ver);
    }
    else
    {
      info = '';
      i = 0;
      foreach line (split(r, keep:FALSE))
      {
        if (++i >= 5) break;
        info += '\n  ' + line;
      }
    }
    telnet_found = TRUE;

    report =
      '\n' + 'It was possible to log into the remote Cisco device via Telnet' +
      '\n' + 'using the following credentials :' +
      '\n';
    if (!pass_only) {
      report +=
        '\n' + '  User     : ' + login;
    }
    report +=
      '\n' + '  Password : ' + password +
      '\n' +
      '\n' + 'and to run the \'show ver\' command, which returned in part :'+
      '\n' +
      info + '\n';
    if (get_kb_item("Settings/PCI_DSS"))
      cisco_pw_report_telnet += '\n' + report;
    else
      security_hole(port:port, extra:report);
  }

# TODO: it could also try 'enable' here and see if it's capable
# of accessing the privilege mode with the same password, or do it
# in a separate module

  close(soc);

 }
}

# Functions modified from the code available from default_accounts.inc
# (which is biased to UNIX)
function check_cisco_account(login, password)
{
 local_var port, ret, banner, soc, res, report;
 local_var buf, i, info, line, ver;

 checking_default_account_dont_report = TRUE;

 if (ssh_port && get_port_state(ssh_port))
 {
  # Prefer login thru SSH rather than telnet
   _ssh_socket= open_sock_tcp(ssh_port);
   if ( _ssh_socket)
   {
   ret = ssh_login(login:login, password:password);
   if (ret == 0) buf = ssh_cmd(cmd:"show ver", nosh:TRUE, nosudo:TRUE, cisco:TRUE);
   else buf = "";
   ssh_close_connection();
   if (
     buf &&
     (
       "Cisco Internetwork Operating System Software" >< buf ||
       "Cisco IOS Software" >< buf ||
       "Cisco IOS XR Software" >< buf ||
       "Cisco IOS XE Software" >< buf ||
       "Cisco Adaptive Security Appliance Software" >< buf
     )
   )
   {
     ver = egrep(pattern:"^.*IOS.*Version [0-9.]+(?:\(.*\))?.*", string:buf);
     if (ver) {
	info = '\n  ' + chomp(ver);
    	if ( !get_kb_item("Host/Cisco/show_ver" ) )
		set_kb_item(name:"Host/Cisco/show_ver", value:ereg_replace(string:ver, pattern:".*(Cisco.*)", replace:"\1"));
	}
     else
     {
       info = '';
       i = 0;
       foreach line (split(buf, keep:FALSE))
       {
         if (++i >= 5) break;
         info += '\n  ' + line;
       }
     }
     ssh_found = TRUE;

     report =
       '\n' + 'It was possible to log into the remote Cisco device via SSH' +
       '\n' + 'using the following credentials :' +
       '\n' +
       '\n' + '  User     : ' + login +
       '\n' + '  Password : ' + password +
       '\n' +
       '\n' + 'and to run the \'show ver\' command, which returned in part :'+
       '\n' +
       info + '\n';
     if (get_kb_item("Settings/PCI_DSS"))
       cisco_pw_report_ssh += '\n' + report;
     else
       security_hole(port:ssh_port, extra:report);
   }
   }
   else
     ssh_port = 0;
 }

 if(telnet_port && get_port_state(telnet_port))
 {
  if ( isnull(password) ) password = "";
  if ( ! telnet_checked )
  {
  banner = get_telnet_banner(port:telnet_port);
  if ( banner == NULL ) { telnet_port = 0 ; return 0; }
  # Check for banner, covers the case of Cisco telnet as well as the case
  # of a console server to a Cisco port
  # Note: banners of cisco systems are not necessarily set, so this
  # might lead to false negatives !
  if ( stridx(banner,"User Access Verification") == -1 && stridx(banner,"assword:") == -1)
    {
     telnet_port = 0;
     return(0);
    }
   telnet_checked ++;
  }

  check_cisco_telnet(login:login, password:password, port:telnet_port);
 }
 if (get_kb_item("Settings/PCI_DSS")) return 0;
 if (ssh_found || telnet_found) exit(0);
 return(0);
}

ssh_port = get_kb_item("Services/ssh");
if ( ! ssh_port ) ssh_port = 22;


telnet_port = get_kb_item("Services/telnet");
if ( ! telnet_port ) telnet_port = 23;
telnet_checked = 0;

check_cisco_account(login:"cisco", password:"cisco");
check_cisco_account(login:"Cisco", password:"Cisco");
check_cisco_account(login:"", password:"");
if ( safe_checks() == 0 || get_kb_item("Settings/PCI_DSS"))
{
 check_cisco_account(login:"cisco", password:"");
 check_cisco_account(login:"admin", password:"cisco");
 check_cisco_account(login:"admin", password:"diamond");
 check_cisco_account(login:"admin", password:"admin");
 check_cisco_account(login:"admin", password:"system");
 check_cisco_account(login:"monitor", password:"monitor");
}

if (get_kb_item("Settings/PCI_DSS"))
{
  if(ssh_found)
    security_hole(port:ssh_port, extra:cisco_pw_report_ssh);
  if(telnet_found)
    security_hole(port:telnet_port, extra:cisco_pw_report_telnet);
  else
    exit(0,"Host not affected.");
}
