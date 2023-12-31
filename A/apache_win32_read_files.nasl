#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11210);
 script_version("1.28");
 script_cvs_date("Date: 2018/11/15 20:50:25");

 script_cve_id("CVE-2003-0017");
 script_bugtraq_id(6660);
 script_xref(name:"Secunia", value:"20493");

 script_name(english:"Apache < 2.0.44 Illegal Character Default Script Mapping Bypass");
 script_summary(english:"Requests /< and gets the output");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a request file disclosure
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of Apache for Windows
that is older than 2.0.44.  Such versions are reportedly affected by a
flaw that allows an attacker to read files that they should not have
access to by appending special characters to them.");
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache 2.0.44 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"see_also", value:"https://marc.info/?l=apache-httpd-announce&m=104313442901017&w=2");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/01/22");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/01/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
 script_end_attributes();

 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2003-2018 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

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
install = get_single_install(app_name:"Apache", port:port);
banner = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);

if ("Win32" >!< banner) audit(AUDIT_WRONG_WEB_SERVER, port, "Apache on Windows");

if (pgrep(pattern:"Apache/(2\.[1-9]|[3-9]|[1-9][0-9])", string:banner)) audit(AUDIT_WRONG_WEB_SERVER, port, "Apache 2.0");

r = http_send_recv3(method:"GET", item:"/<<<<<<<<<<<<", port:port);
# Apache 2.0.44 replies with a code 403
if (preg(pattern:"^HTTP/[0-9]\.[0-9] 301 ", string:r[0]))
{
  # Unless we're paranoid, check that the initial page doesn't return a 301 normally.
  if (report_paranoia < 2)
  {
    r = http_send_recv3(method:"GET", item:"/", port:port);
    if (preg(pattern:"^HTTP/[0-9]\.[0-9] 301 ", string:r[0])) exit(0, "The web server listening on port "+port+" returns a 301 for the initial page normally.");
  }

  security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Apache", port);
