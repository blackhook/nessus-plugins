#
# (C) Tenable Network Security, Inc.
#

#
# The real DoS will be performed by plugin#10930, so we just check
# the banner 
#


include("compat.inc");

if(description)
{
 script_id(11209);
 script_version("1.24");
 script_cvs_date("Date: 2018/06/29 12:01:03");

 script_cve_id("CVE-2003-0016");
 script_bugtraq_id(6659);
 script_xref(name:"Secunia", value:"20493");
 
 script_name(english:"Apache < 2.0.44 DOS Device Name Multiple Remote Vulnerabilities (Code Exec, DoS)");
 script_summary(english:"Checks for version of Apache");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple remote vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of
Apache for Windows that is older than 2.0.44.

There are several flaws in this version that allow
an attacker to crash this host or even execute arbitrary
code remotely, but it only affects WindowsME and Windows9x.

*** Note that Nessus solely relied on the version number
*** of the remote server to issue this warning. This might
*** be a false positive." );
 script_set_attribute(attribute:"see_also", value:
"http://www-01.ibm.com/support/docview.wss?uid=swg1IC48645" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache 2.0.44 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/01/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/01/20");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:apache:http_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2003-2018 Tenable Network Security, Inc.");

 script_dependencies("apache_http_version.nasl");
 script_require_keys("installed_sw/Apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

get_install_count(app_name:"Apache", exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:"Apache", port:port, exit_if_unknown_ver:TRUE);
banner = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.0\.(([0-3][0-9][^0-9])|(4[0-3][^0-9])).*Win32.*", string:serv))
{
  security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, install["version"]);
