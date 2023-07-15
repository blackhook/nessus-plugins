#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11391);
 script_version("1.27");
 script_cvs_date("Date: 2018/08/31 12:25:01");

 script_cve_id("CVE-2000-0574");
 script_bugtraq_id(1425, 1438);

 script_name(english:"Multiple FTP Server setproctitle Function Arbitrary Command Execution");
 script_summary(english:"Checks if the remote ftpd is vulnerable to format string attacks");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is susceptible to a remote command execution
attack.");
 script_set_attribute(attribute:"description", value:
"The remote FTP server misuses the function setproctitle() and may
allow an attacker to gain a root shell on this host by logging in as
'anonymous' and providing a carefully crafted format string as its
email address.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aee65ddc");
 script_set_attribute(attribute:"solution", value:"Install the latest patches from your vendor.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/07/05");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/15");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"FTP");

 script_copyright(english: "This script is Copyright (C) 2003-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/anonymous", "Settings/ParanoidReport");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ftp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_ftp_port(default: 21);

# Connect to the FTP server
soc = open_sock_tcp(port);
if (! soc) exit(1);

ftp_debug(str:"custom banner");
banner = ftp_recv_line(socket:soc);
if(!banner)exit(1);

 send(socket:soc, data:'USER anonymous\r\n');
 r = ftp_recv_line(socket:soc);
 if(!egrep(pattern:"^331", string:r))exit(0);
 send(socket:soc, data:'PASS %n%n%n%n%n%n%n\r\n');
 r = ftp_recv_line(socket:soc);
 if(!r || !egrep(pattern:"^230",  string:r))exit(0);
 send(socket:soc, data:'HELP\r\n');
 r = recv_line(socket:soc, length:4096);
 if(!r)security_warning(port);

