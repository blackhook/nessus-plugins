#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(14591);
 script_cve_id("CVE-2004-1641");
 script_bugtraq_id(11069);
 script_version("1.17");

 script_name(english:"Titan FTP Server Multiple Command Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a 
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote is running Titan FTP Server. All versions up to 
and including 3.21 are reported vulnerable to a remote heap 
overflow in the CWD, STAT or LIST command processing.

An attacker may deny service to legitimate users or execute 
arbitrary code on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Titan FTP 3.22 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2004-1641");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/31");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/31");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/02");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2023 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencies("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

include("ftp_func.inc");
include("debug.inc");

var port = get_ftp_port(default: 21);
var banner = get_ftp_banner(port:port);
dbg::detailed_log(lvl:2,msg:banner);

if (pgrep(pattern:"^220.*Titan FTP Server ([0-2]\.|3\.([0-9][^0-9]|[0-1][0-9]|2[0-1])[^0-9])", string:banner)) 
	security_hole(port);

