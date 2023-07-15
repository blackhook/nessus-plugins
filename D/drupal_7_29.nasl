#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76619);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2014-5019",
    "CVE-2014-5020",
    "CVE-2014-5021",
    "CVE-2014-5022"
  );
  script_bugtraq_id(68706);

  script_name(english:"Drupal 6.x < 6.32 / 7.x < 7.29 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running a version of Drupal that is 6.x prior
to 6.32 or 7.x prior to 7.29. It is, therefore, potentially affected
by the following vulnerabilities :

  - The HTTP Host header, which determines the configuration
    file used by Drupal core's multisite feature, does not
    properly validate header values, which may result in a
    denial of service. This may also affect sites that do
    not use the multisite feature. (CVE-2014-5019)

  - The File module in Drupal 7.x does not properly check
    file permissions when creating attachments. This may
    allow attackers to gain access to arbitrary files.
    (CVE-2014-5020)

  - The form API does not properly sanitize option group
    labels in select elements, which may allow unspecified
    cross-site scripting attacks. (CVE-2014-5021)

  - Forms containing a combination of an Ajax-enabled text
    field and a file field may contain an unspecified
    cross-site scripting vulnerability. (CVE-2014-5022)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/SA-CORE-2014-003");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/drupal-7.29-release-notes");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/6.32");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 6.32 / 7.29 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-5020");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Drupal";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
url = build_url(qs:dir, port:port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = NULL;

if (version =~ "^6\.([0-9]|[1-2][0-9]|3[0-1])($|[^0-9]+)") fix = '6.32';
else if (version =~ "^7\.([0-9]|1[0-9]|2[0-8])($|[^0-9]+)") fix = '7.29';

if (fix)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
