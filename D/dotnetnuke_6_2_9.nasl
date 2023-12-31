#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(70294);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2013-3943", "CVE-2013-4649", "CVE-2013-7335");
  script_bugtraq_id(61770, 61809);

  script_name(english:"DNN (DotNetNuke) < 6.2.9 / 7.1.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP.NET application that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of DNN installed on the remote host is affected by
multiple vulnerabilities :

  - The application is affected by a persistent cross-site
    scripting vulnerability because input to the
    'Display Name' in the 'Manage Profile' view is not
    properly sanitized. (CVE-2013-3943)

  - The application is affected by a cross-site scripting
    vulnerability because user-supplied input to the
    '__dnnVariable' parameter is not properly sanitized.
    (CVE-2013-4649)

  - An unspecified open redirect flaw exists that can
    allow an attacker to perform a phishing attack by
    enticing a user to click on a malicious URL.
    (CVE-2013-7335)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.dnnsoftware.com/community/security/security-center");
  script_set_attribute(attribute:"solution", value:
"Upgrade to DNN version 6.2.9 / 7.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dotnetnuke:dotnetnuke");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dotnetnuke_detect.nasl");
  script_require_keys("installed_sw/DNN");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "DNN";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, asp:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];

install_url = build_url(qs:dir, port:port);

if (version =~ '(^6(\\.2)?$)|(^7(\\.1)?$)')
  audit(AUDIT_VER_NOT_GRANULAR, app, port, version);

fix = NULL;

# Versions less than 6.2.9 / 7.1.1 are vulnerable
if (version =~ "^[0-5]\.")
  fix = "6.2.9 / 7.1.1";
else if (version =~ "^6\." && (ver_compare(ver:version, fix:'6.2.9', strict:FALSE) == -1))
  fix = "6.2.9";
else if (version =~ "^7\." && (ver_compare(ver:version, fix:'7.1.1', strict:FALSE) == -1))
  fix = "7.1.1";

if (!isnull(fix))
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : ' +fix+ '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
