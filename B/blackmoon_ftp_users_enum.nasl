#
# (C) Tenable Network Security, Inc.
#
# ref: https://marc.info/?l=bugtraq&m=105353283720837&w=2
#


include("compat.inc");


if(description)
{
 script_id(11648);
 script_cve_id("CVE-2003-0343");
 script_bugtraq_id(7647);
 script_xref(name:"Secunia", value:"8840");
 script_version ("1.20");
 
 script_name(english:"BlackMoon FTP Login Error Message User Enumeration");
 script_summary(english:"Checks for the ftp login error message");
	     
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote FTP server has a user enumeration vulnerability."
 );
 script_set_attribute( attribute:"description",  value:
"The version of BlackMoon FTP running on the remote host issues a
special error message when a user attempts to log in using a
nonexistent account.

An attacker may use this flaw to make a list of valid accounts,
which can be used to mount further attacks." );
 script_set_attribute(
   attribute:"see_also",
   value:"https://marc.info/?l=bugtraq&m=105353283720837&w=2"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of BlackMoon FTP."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/20");
 script_cvs_date("Date: 2018/11/15 20:50:22");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 script_copyright(english:"This script is Copyright (C) 2003-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_dependencies("ftpserver_detect_type_nd_version.nasl", "logins.nasl", "smtp_settings.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_ftp_port(default: 21);

soc = open_sock_tcp(port);
if (! soc) exit(1, "Cannot connect to TCP port "+port+".");

 ftp_debug(str:"custom banner");
 banner = ftp_recv_line(socket:soc);
 if (!banner) exit(1, "Cannot read FTP banner from port "+port+".");
 send(socket:soc, data:('USER nessus' + rand() + rand() + '\r\n'));
 r = recv_line(socket:soc, length:4096);
 if(!r)exit(0);
 
 send(socket:soc, data:('PASS whatever\r\n'));
 r = recv_line(socket:soc, length:4096);
 if(!r) exit(0);
 close(soc);
 if("530-Account does not exist" >< r) security_warning(port);

