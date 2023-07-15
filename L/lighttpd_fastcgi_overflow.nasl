#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26057);
  script_version("1.20");

  script_cve_id("CVE-2007-4727");
  script_bugtraq_id(25622);

  script_name(english:"lighttpd mod_fastcgi HTTP Request Header Remote Overflow");
  script_summary(english:"Sends a long header to lighttpd.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server appears to be lighttpd running with the FastCGI
module (mod_fastcgi). The version of the FastCGI module on the remote
host is affected by a buffer overflow vulnerability. A remote attacker
can exploit this, by sending a specially crafted request with a long
header, to add or replace headers passed to PHP, such as
SCRIPT_FILENAME, which in turn could result in arbitrary code
execution.");
  # https://web.archive.org/web/20080120064737/http://www.secweb.se/en/advisories/lighttpd-fastcgi-remote-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b18fbfb0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to lighttpd version 1.4.18 or later. Alternatively, disable
the FastCGI module.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(119);


  script_set_attribute(attribute:"plugin_publication_date", value: "2007/09/17");
  script_set_attribute(attribute:"vuln_publication_date", value: "2007/09/10");

  script_cvs_date("Date: 2018/07/13 15:08:46");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lighttpd:lighttpd");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2007-2018 Tenable Network Security, Inc.");

  script_dependencies("lighttpd_detect.nasl");
  script_require_keys("installed_sw/lighttpd", "www/php");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("install_func.inc");

get_install_count(app_name:"lighttpd", exit_if_zero:TRUE);
port = get_http_port(default:80, embedded:TRUE, php:TRUE);
install = get_single_install(app_name:"lighttpd", port:port);

# Make sure the server itself works.
url = "/";
rq = http_mk_get_req(item:url, port:port);
w = http_send_recv_req(port: port, req: rq);
if (isnull(w)) exit(1, "The web server on port "+port+" did not answer.");

# If it does...
if (w[0] =~ "^HTTP/.* 200 ")
{
  # Send the same request but with a long header.
      # nb: the size of the environment needs to exceed FCGI_MAX_LENGTH, 
      #     as defined in src/fastcgi.h. By default, it's 0xffff so 
      #     this is probably more than what we need.
  rq['Nessus'] = crap(0xffff);
  w = http_send_recv_req(port: port, req: rq);
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer.");

  # There's a problem unless we get a 400 (bad request) or 431
  # (request header too long) response.
  if (w[0] !~ "^HTTP/.* (400|431) ")
  {
    security_warning(port);
    exit(0);
  }
}

audit(AUDIT_LISTEN_NOT_VULN, "lighttpd", port, install["version"]);
