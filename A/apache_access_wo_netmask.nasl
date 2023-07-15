#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

include("compat.inc");

if (description)
{
  script_id(14177);
  script_version("1.31");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

  script_cve_id("CVE-2003-0993");
  script_bugtraq_id(9829);
  script_xref(name:"GLSA", value:"GLSA 200405-22");
  script_xref(name:"MDKSA", value:"MDKSA-2004:046");
  script_xref(name:"SSA", value:"SSA:2004-133-01");
  script_xref(name:"Secunia", value:"11088");
  script_xref(name:"Secunia", value:"11681");
  script_xref(name:"Secunia", value:"11719");
  script_xref(name:"Secunia", value:"12246");

  script_name(english:"Apache < 1.3.31 mod_access IP Address Netmask Rule Bypass");
  script_summary(english:"Checks for Apache version");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an access control bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Apache web server prior to
1.3.31. It is, therefore, affected by an access control bypass
vulnerability due to a failure, on big-endian 64-bit platforms, to
properly match 'allow' or 'deny' rules that contain an IP address but
lack a corresponding netmask.

Nessus has determined the vulnerability exists only by looking at the
Server header returned by the web server running on the target. If the
target is not a big-endian 64-bit platform, consider this a false
positive.");
  script_set_attribute(attribute:"see_also", value:"http://www.apacheweek.com/features/security-13");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=apache-cvs&m=107869603013722" );
  script_set_attribute(attribute:"see_also", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=23850" );
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache web server version 1.3.31 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2020 George A. Theall");
  script_family(english:"Web Servers");

  script_dependencie("apache_http_version.nasl", "ssh_get_info.nasl");
  script_require_keys("installed_sw/Apache", "Settings/ParanoidReport");   
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("http_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

uname = get_kb_item("Host/uname");
if ( uname )
{
 if ( pgrep(pattern:"i.86", string:uname) ) exit(0);
}
host = get_host_name();
port = get_http_port(default:80, embedded:TRUE);

if (!get_port_state(port)) exit(0);

# Check the web server's banner for the version.
banner = get_http_banner(port:port);
if (!banner) exit(0);
banner = get_backport_banner(banner:banner);

sig = strstr(banner, "Server:");
if (!sig) exit(0);

if(preg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/1\.([0-2]\.[0-9]|3\.([0-9][^0-9]|[0-2][0-9]))", string:sig)) {
  security_hole(port);
}
