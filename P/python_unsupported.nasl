#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(148367);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/30");

  script_name(english:"Python Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains one or more unsupported versions of Python.");
  script_set_attribute(attribute:"description", value:
"The remote host contains one or more unsupported versions of Python.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");

  script_set_attribute(attribute:"see_also", value:"https://www.python.org/downloads/");
  script_set_attribute(attribute:"see_also", value:"https://devguide.python.org/devcycle/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Python that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported software.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:python:python");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("python_http_remote_detection.nbin");
  script_require_keys("installed_sw/Python");
  exit(0);
}

include("install_func.inc");
include("http.inc");
include("backport.inc");
include("spad_log_func.inc");

app = 'Python';
cpe = 'cpe:/a:python:python';

#if no installs found then exit
get_install_count(app_name:app, exit_if_zero:TRUE);

# For display
latest_versions = '3.10';

# Longterm support data
longterm_support_lists = make_array(
 "^1\."                , 'No support dates are available.',
 "^2\.[0-5](?:[^\d]|$)", 'No support dates are available.',
 "^2\.6(?:[^\d]|$)"    , '2013-10-29 (end of life)',
 "^2\.7(?:[^\d]|$)"    , '2020-01-01 (end of life)',
 "^3\.0(?:[^\d]|$)"    , '2009-06-27 (end of life)',
 "^3\.1(?:[^\d]|$)"    , '2012-04-09 (end of life)',
 "^3\.2(?:[^\d]|$)"    , '2016-02-20 (end of life)',
 "^3\.3(?:[^\d]|$)"    , '2017-09-29 (end of life)',
 "^3\.4(?:[^\d]|$)"    , '2019-03-18 (end of life)',
 "^3\.5(?:[^\d]|$)"    , '2020-09-30 (end of life)'
);

##
#  Leverage scan time to keep this plugin up-to-date using output
#  from the date utility like so 'date +%s --date="July 1, 2022"' (gives us 1656648000)
#  Using the start_time kb value instead of gettimeofday() to aid in flatline testing
##
now = get_kb_item("/tmp/start_time");
# 3.6: Dec 23, 2021
if (now > 1640217600)  
  longterm_support_lists["^3\.6(?:[^\d]|$)"] = '2021-12-23 (end of life)';

# 3.7: Jun 27, 2023
if (now > 1687824000)
  longterm_support_lists["^3\.7(?:[^\d]|$)"] = '2023-06-27 (end of life)';

# 3.8: October 14, 2024
if (now > 1728864000)
  longterm_support_lists["^3\.8(?:[^\d]|$)"] = '2024-10-14 (end of life)';

# 3.9: October 5, 2025
if (now > 1759622400)
  longterm_support_lists["^3\.9(?:[^\d]|$)"] = '2025-10-05 (end of life)';

# 3.10: October 4, 2026
if (now > 1791072000)
  longterm_support_lists["^3\.10(?:[^\d]|$)"] = '2026-10-04 (end of life)';

#Grabs both local and remote
install = get_single_install(app_name:app, combined:TRUE, exit_if_unknown_ver:TRUE);

# See if any installs are unsupported..
if(!empty_or_null(install))
{
  # Multiple installs can be found, so using the backport indicator found in the kb rather than the global var
  # this also makes testing easier
  var backport = install['Backported'];
  if(empty_or_null(backport))
    backport = FALSE;
  # if this install is backported then ignore it
  if(report_paranoia < 2 && backport)
  {
    spad_log(message:strcat('Python Web Server listening on port ', install['port'], ' appears be backported.'));
    audit(AUDIT_BACKPORT_SERVICE, install['port'], 'Python Web Server');
  }

  version = install['version'];
  foreach var pattern (keys(longterm_support_lists))
  {
    if (version !~ pattern) continue;

    support_dates = longterm_support_lists[pattern];

    register_unsupported_product(product_name : app,
                                 version      : version,
                                 cpe_base     : 'python:python');

    report +=
      '\n  Path              : ' + install['path'];
    if(!empty_or_null(install['port']))
      report += '\n  Port              : ' + install['port'];
    report = strcat(report, 
      '\n  Installed version : ', version,
      '\n  Latest version    : ', latest_versions,
      '\n  Support dates     : ', support_dates,
      '\n');

  }
}

# ...then report on any that were found
if (strlen(report))
{
  report = '\nThe following Python installation is unsupported :\n' + report;
  security_report_v4(port:install['port'], extra:report, severity:SECURITY_HOLE);
}
else
{
  audit(AUDIT_NOT_INST, "An unsupported version of Python");
}
