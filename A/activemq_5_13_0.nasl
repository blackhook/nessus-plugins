#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87410);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2015-5254");
  script_xref(name:"CERT", value:"576313");

  script_name(english:"Apache ActiveMQ 5.x < 5.13.0 Java Object Deserialization RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache ActiveMQ running on the remote host is 5.x prior
to 5.13.0. It is, therefore, affected by a remote code execution
vulnerability in the broker due to unsafe deserialize calls of
unauthenticated Java objects to the Apache Commons Collections (ACC)
library. An unauthenticated, remote attacker can exploit this to
execute arbitrary code on the target host.");
  # http://activemq.apache.org/security-advisories.data/CVE-2015-5254-announcement.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?863a18c3");
  # https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c6d83db");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache ActiveMQ version 5.13.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5254");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:activemq");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("activemq_web_console_detect.nasl");
  script_require_keys("installed_sw/ActiveMQ", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8161);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'ActiveMQ';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8161);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
install_url = build_url(port:port, qs:dir);

if (report_paranoia < 2) audit(AUDIT_PARANOID);
fix = '5.13.0';

vuln = FALSE;
if (version =~ "^5\.12\.")
{
  if (ver_compare(ver:version, fix:"5.12.1", strict:FALSE) <= 0)
   vuln = TRUE;
}
else if (version =~ "^5\.11\.")
{
  if (ver_compare(ver:version, fix:"5.11.3", strict:FALSE) <= 0)
   vuln = TRUE;
}
else if (version =~ "^5\.([0-9]|10)(\.|$)")
  vuln = TRUE;

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else
    security_hole(port);

  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
