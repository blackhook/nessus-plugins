#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11361);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_cve_id("CVE-2003-1245");
  script_bugtraq_id(6926);

  script_name(english:"Mambo Site Server MD5 Hash Session ID Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote installation of Mambo Site Server improperly validates the
cookies that are sent back by the user.  As a result, a user may
impersonate the administrator by using the MD5 value of a received
cookie and thereby gain administrative control of the affected
application.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2003/Feb/304");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mambo 4.0.12 RC3 or newer.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2022 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl");
  script_require_keys("www/mambo_mos");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
init_cookiejar();
if (!isnull(matches)) {
 dir = matches[2];

 r = http_send_recv3(method: "GET", item:string(dir, "/index.php?option=logout"), port:port);
 if (isnull(r)) exit(0);
 cookie = egrep(pattern: "^Set-Cookie.*sessioncookie", string: r[1], icase: TRUE);
 if(cookie)
 {
  id = ereg_replace(pattern:".*=(.*)", string: chomp(cookie), replace:"\1");
  req = http_send_recv3(method: "GET", item:string(dir, "/administrator/index2.php?session_id=", hexstr(MD5(id))), port:port);
  if("Mambo Open Source - Administration" >< r[2]) {
    security_hole(port);
    exit(0);
  }
 }
}
