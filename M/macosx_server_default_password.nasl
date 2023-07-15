#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if (description)
{
 script_id(12513);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2017/11/20 15:32:08 $");

 script_cve_id("CVE-1999-0502");

 script_name(english:"Default Password (12345678) for 'root' Account on MacOS X Server");
 script_summary(english:"Logs into the remote host");

 script_set_attribute(
   attribute:"synopsis",
   value:"A default account was detected on the remote host."
 );
 script_set_attribute(
   attribute:"description",
   value:
"Nessus was able to login to the remote host using the following
credentials :

  Username : root
  Password : 12345678

On older Macintosh computers, Mac OS X server is configured with
this default account (on newer computers, the serial number of the
system is used instead)." );
 script_set_attribute(
   attribute:"solution",
   value:"Set a strong password for the root account."
 );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SSH User Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Default Unix Accounts");

 script_copyright(english:"This script is Copyright (C) 2004-2017 Tenable Network Security, Inc.");

 script_dependencie("ssh_detect.nasl", "os_fingerprint.nasl", "account_check.nasl");
 script_require_ports("Services/ssh", 22);
 script_exclude_keys("global_settings/supplied_logins_only");
 exit(0);
}

#
# The script code starts here :
#
include("audit.inc");
include("default_account.inc");
include("global_settings.inc");

os = get_kb_item_or_exit("Host/OS");
if ("Mac OS X" >!< os) audit(AUDIT_OS_NOT, "Mac OS X");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

account = "root";
password = "12345678";

affected = FALSE;
ssh_ports = get_service_port_list(svc: "ssh", default:22);
foreach port (ssh_ports)
{
  port = check_account(login:account, password:password, port:port, svc:"ssh");
  if (port)
  {
    affected = TRUE;
    security_report_v4(port:port, severity:SECURITY_HOLE, extra:default_account_report());
  }
}
if(affected) exit(0);

telnet_ports = get_service_port_list(svc: "telnet", default:23);
foreach port (telnet_ports)
{
  port = check_account(login:account, password:password, port:port, svc:"telnet");
  if (port)
  {
    affected = TRUE;
    security_report_v4(port:port, severity:SECURITY_HOLE, extra:default_account_report());
  }
}
if(!affected) audit(AUDIT_HOST_NOT, "affected");