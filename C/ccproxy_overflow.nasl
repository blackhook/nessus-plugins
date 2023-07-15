#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(15774);
 script_version ("1.15");
 script_cve_id("CVE-2004-2416");
 script_bugtraq_id(11666);
 script_xref(name:"EDB-ID", value:"619");
 script_xref(name:"Secunia", value:"13085");

 script_name(english:"CCProxy Logging Compoent HTTP GET Request Remote Overflow");
 script_summary(english:"Does a version check");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote proxy has a buffer overflow vulnerability."
 );
 script_set_attribute(attribute:"description", value:
"The version of CCProxy running on the remote host has a buffer
overflow vulnerability.  This issue is triggered by sending a long
HTTP GET request.  A remote attacker could exploit this issue to
crash the service, or potentially execute arbitrary code." );
 script_set_attribute(
   attribute:"see_also",
   value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/18012"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.securiteam.com/exploits/6E0032KBPM.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to CCProxy version 6.3 or later."
 );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CCProxy Telnet Proxy Ping Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/05");
 script_cvs_date("Date: 2018/06/27 18:42:26");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");
 
 script_copyright(english:"This script is Copyright (C) 2004-2018 Tenable Network Security, Inc.");
 
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/ccproxy-smtp");
 exit(0);
}

#
# The script code starts here
#
include("smtp_func.inc");
port = get_kb_item("Services/ccproxy-smtp");
if ( ! port ) exit(0);
banner = get_smtp_banner ( port:port);
if ( egrep(pattern:"CCProxy ([0-5]\.|6\.[0-2]) SMTP Service Ready", string:banner) )
	security_hole ( port );

