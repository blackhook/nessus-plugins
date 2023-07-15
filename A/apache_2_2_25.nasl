#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68915);
  script_version("1.18");
  script_cvs_date("Date: 2018/06/29 12:01:03");

  script_cve_id("CVE-2013-1862", "CVE-2013-1896");
  script_bugtraq_id(59826, 61129);

  script_name(english:"Apache 2.2.x < 2.2.25 Multiple Vulnerabilities");
  script_summary(english:"Checks version in Server response header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server may be affected by multiple cross-site scripting
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache 2.2.x running on the
remote host is prior to 2.2.25. It is, therefore, potentially affected
by the following vulnerabilities :

  - A flaw exists in the 'RewriteLog' function where it
    fails to sanitize escape sequences from being written
    to log files, making it potentially vulnerable to
    arbitrary command execution. (CVE-2013-1862)

  - A denial of service vulnerability exists relating to
    the 'mod_dav' module as it relates to MERGE requests.
    (CVE-2013-1896)

Note that Nessus did not actually test for these issues, but instead
has relied on the version in the server's banner.");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.2.25");
  script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/security/vulnerabilities_22.html");
  # http://mail-archives.apache.org/mod_mbox/httpd-announce/201307.mbox/%3C20130710125106.635ba5a2.wrowe@rowe-clan.net%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f050c342");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.2.25 or later. Alternatively, ensure that
the affected modules are not in use.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");

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

# Check if we could get a version first, then check if it was
# backported
version = get_kb_item_or_exit('www/apache/'+port+'/version', exit_code:1);
backported = get_kb_item_or_exit('www/apache/'+port+'/backported', exit_code:1);

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "Apache web server");
source = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);

# Check if the version looks like either ServerTokens Major/Minor was used.
if (version =~ '^2(\\.2)?$') exit(1, "The banner from the Apache server listening on port "+port+" - "+source+" - is not granular enough to make a determination.");

# This plugin is only concerned with Apache 2.2
if (version !~ "^2\.2[^0-9]") audit(AUDIT_WRONG_WEB_SERVER, port, "Apache 2.2.x");

fixed_ver = '2.2.25';
if (ver_compare(ver:version, fix:fixed_ver) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_ver + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, version);
