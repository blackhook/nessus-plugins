#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(12293);
 script_version("1.27");
 script_cvs_date("Date: 2018/06/29 12:01:03");

 script_cve_id("CVE-2004-0493", "CVE-2004-0748");
 script_bugtraq_id(10619, 12877);
  
 script_name(english:"Apache 2.x < 2.0.50 Multiple Remote DoS");
 script_summary(english:"Checks for version of Apache");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of Apache 2.x that is
prior to 2.0.50. It is, therefore, affected by a denial of service
vulnerability that can be triggered by sending a specially crafted
HTTP request, which results in the consumption of an arbitrary amount
of memory. On 64-bit systems with more than 4GB virtual memory, this
may lead to a heap based buffer overflow.

There is also a denial of service vulnerability in mod_ssl's
'ssl_io_filter_cleanup' function. By sending a request to a vulnerable
server over SSL and closing the connection before the server can send
a response, an attacker can cause a memory violation that crashes the
server." );
 script_set_attribute(attribute:"see_also", value:"http://www.guninski.com/httpd1.html");
 script_set_attribute(attribute:"solution", value:"Upgrade to Apache 2.0.50 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/06/29");
 script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/28");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:apache:http_server");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2018 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencies("apache_http_version.nasl");
 script_require_keys("installed_sw/Apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

get_install_count(app_name:"Apache", exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:"Apache", port:port, exit_if_unknown_ver:TRUE);
banner = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);
 
if(pgrep(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.0\.(([0-9][^0-9])([0-3][0-9][^0-9])|(4[0-9][^0-9])).*", string:banner))
{
  security_warning(port);
  exit(0);
}

audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, install["version"]);
