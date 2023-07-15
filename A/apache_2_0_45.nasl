#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11507);
  script_version("1.39");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2003-0132");
  script_bugtraq_id(7254, 7255);

  script_name(english:"Apache 2.0.x < 2.0.45 Multiple Vulnerabilities (DoS, File Write)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Apache 2.0.x that is prior to
2.0.45. It is, therefore, reportedly affected by multiple
vulnerabilities :

  - There is a denial of service attack that could allow an
    attacker to disable this server remotely.

  - The httpd process leaks file descriptors to child
    processes, such as CGI scripts. An attacker who has the
    ability to execute arbitrary CGI scripts on this server
    (including PHP code) would be able to write arbitrary
    data in the file pointed to (in particular, the log
    files).");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache web server version 2.0.45 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/04/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2003-2022 Tenable Network Security, Inc.");

  script_dependencies("no404.nasl", "apache_http_version.nasl");
  script_require_keys("installed_sw/Apache", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_install_count(app_name:"Apache", exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:"Apache", port:port, exit_if_unknown_ver:TRUE);

# Check if we could get a version
version = get_kb_item_or_exit('www/apache/'+port+'/version', exit_code:1);
if (version !~ "^\d+(\.\d+)*$") exit(1, "The version of Apache listening on port " + port + " - " + version + " - is non-numeric and, therefore, cannot be used to make a determination.");

if( safe_checks() )
{
  source = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);

  # Check if the version looks like either ServerTokens Major/Minor
  # was used.
  if (version =~ '^2(\\.0)?$') exit(1, "The banner from the Apache server listening on port "+port+" - "+source+" - is not granular enough to make a determination.");
  if (version =~ '^2\\.0' && ver_compare(ver:version, fix:'2.0.45') == -1)
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  Version source    : ' + source +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 2.0.45\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
  else audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, install["version"]);
}
else
{
  if (ver_compare(ver:version, fix:'2.0.45') >= 0)
    exit(0);

  soc = open_sock_tcp(port);
  for (i=0; i<101; i++)
  {
    n = send(socket:soc, data:'\r\n');
    if (n <= 0) exit(0);
  }

  r = http_recv_headers3(socket:soc);
  if (!r) security_warning(port);
}
