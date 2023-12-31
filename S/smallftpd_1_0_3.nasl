#
# This script was written by Audun Larsen <larsen@xqus.com>
#
# Changes by Tenable:
# - Revised plugin title, changed family (2/03/2009)
# - Updated to use compat.inc, added CVSS score (11/20/2009)




include("compat.inc");

if (description)
{
 script_id(12072);
 script_version("1.24");
 script_cvs_date("Date: 2019/02/26  4:50:08");

 script_cve_id("CVE-2004-0299");
 script_bugtraq_id(9684, 40180, 48453, 58856);
 script_xref(name:"EDB-ID", value:"15358");

 script_name(english:"smallftpd 1.0.3 Multiple DoS");
 script_summary(english:"Checks for version of smallftpd");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running a version of Smallftpd that is
1.0.3 or earlier.  Such versions are reportedly affected by denial of
service and directory traversal vulnerabilities.");
 script_set_attribute(attribute:"solution", value:
"Either disable the service or switch to a different FTP server as
Smallftpd has not been updated since 2004.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2004-0299");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/17");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/02/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2019 Audun Larsen");
 script_family(english:"FTP");
 script_dependencies("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("ftp_func.inc");

port = get_ftp_port(default: 21);
banner = get_ftp_banner(port:port);
if (! banner) audit(AUDIT_NO_BANNER,port);
if(pgrep(pattern:"^220.*smallftpd (0\..*|1\.0\.[0-3]($|[^0-9]))", string:banner) )
{
  security_warning(port);
  exit(0);
}
audit(AUDIT_NOT_LISTEN,"Smallftpd",port);
