#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(16208);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2004-2218");
  script_bugtraq_id(10942);

  script_name(english:"phpMyWebHosting Authentication SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary SQL statements may be executed on the remote database.");
  script_set_attribute(attribute:"description", value:
"The remote host is running PHPMyWebHosting, a web hosting management 
interface written in PHP.

The remote version of this software does not perform a proper validation
of user-supplied input and is, therefore, vulnerable to a SQL injection
attack.

An attacker may execute arbitrary SQL statements against the remote 
database by sending a malformed username containing SQL escape 
characters when logging into the remote interface in 'login.php'.");
  script_set_attribute(attribute:"solution", value:
"None at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmywebhosting:phpmywebhosting");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
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


variables = string("PHP_AUTH_USER='&password=&language=english&submit=login");

port = get_http_port(default:80);


foreach dir ( cgi_dirs() )
{
  r = http_send_recv3(method: "POST", item: strcat(dir, "/index.php"), port: port, add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"), data: variables, exit_on_fail: TRUE);
 buf = strcat(r[0], r[1], '\r\n', r[2]);
 if ( "SQL" >< buf &&
      " timestamp > date_add" >< buf  && "INTERVAL " >< buf)
   {
     set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
     security_hole(port);
   }
}
audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);
