#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86721);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2015-6576");
  script_bugtraq_id(77292);

  script_name(english:"Atlassian Bamboo 2.2.x < 5.8.5 / 5.9.x < 5.9.7 Unspecified Resource Deserialization RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of
Atlassian Bamboo running on the remote host is version 2.2.x prior to
5.8.5 or 5.9.x prior to 5.9.7. It is, therefore, affected by an
unspecified resource deserialization flaw due to improper validation
of user-supplied input. An unauthenticated, remote attacker can
exploit this to execute arbitrary Java code. Note that the attacker
must be able to access the Bamboo web interface.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://confluence.atlassian.com/bamboo/bamboo-security-advisory-2015-10-21-785452575.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?70364dac");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/BAM-16439");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Bamboo version 5.8.5 / 5.9.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6576");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:bamboo");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bamboo_detect.nbin");
  script_require_keys("installed_sw/bamboo");
  script_require_ports("Services/www", 8085);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Bamboo";
app_name = tolower(app);

get_install_count(app_name:app_name, exit_if_zero:TRUE);

port = get_http_port(default:8085);

install = get_single_install(
  app_name : app_name,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir     = install['path'];
version = install['version'];

install_url = build_url(port:port, qs:dir);
vuln = FALSE;

if (version =~ "^5\.[89]$")
  audit(AUDIT_VER_NOT_GRANULAR, app, port, version);

if (version =~ "^(2\.[2-9]|[34]\.|5\.[0-7]($|\.|[^0-9]))")
{
  vuln = TRUE;
  fix_ver = "5.8.5 / 5.9.7";
}
else if (version =~ "^5\.8\.[0-4]($|[^0-9])")
{
  vuln = TRUE;
  fix_ver = "5.8.5";
}
else if (version =~ "^5\.9\.[0-6]($|[^0-9])")
{
  vuln = TRUE;
  fix_ver = "5.9.7";
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  URL               : ' + install_url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix_ver + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
