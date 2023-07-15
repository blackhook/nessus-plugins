#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91501);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/08");
  script_xref(name:"IAVA", value:"0001-A-0549");

  script_name(english:"McAfee VirusScan Enterprise for Linux Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an unsupported version of McAfee VSEL.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of McAfee VirusScan
Enterprise for Linux (VSEL) on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # https://www.mcafee.com/enterprise/en-us/support/product-eol.html#product=virusscan_enterprise
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c5d29f3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of McAfee VirusScan Enterprise for Linux (VSEL)
that is currently supported.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported products.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:virusscan_enterprise");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2022 Tenable Network Security, Inc.");

  script_dependencies("mcafee_vsel_detect.nbin");
  script_require_keys("installed_sw/McAfee VirusScan Enterprise for Linux");

  exit(0);
}

include('install_func.inc');

var app_name = "McAfee VirusScan Enterprise for Linux";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

var install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
var version = install['version'];

# format check
if (!preg(pattern:"^\d{1,2}(\.\d|$)", string:version)) audit(AUDIT_VER_FORMAT, version);
# granularity check
if (preg(pattern:"^1([^0-9\.]|$)", string:version)) audit(AUDIT_VER_NOT_GRANULAR, app_name, version);

var eol_versions =
  make_array(
    "^0(\.[0-9]|$)", make_array(
      'eol_date', 'No Date Available',
      'kb', 'No Announcement Available'
      ),
    "^1\.[0-5]", make_array(
      'eol_date', 'No Date Available',
      'kb', 'No Announcement Available'
      ),
    "^1\.6", make_array(
      'eol_date', 'June 15 2014',
      'kb', 'https://kc.mcafee.com/corporate/index?page=content&id=KB78458'
      ),
    "^1\.7", make_array(
      'eol_date', 'September 30 2015',
      'kb', 'https://kc.mcafee.com/corporate/index?page=content&id=KB84073'
      ),
    "^1\.8", make_array(
      'eol_date', 'September 30 2015',
      'kb', 'https://www.mcafee.com/enterprise/en-us/support/product-eol.html#product=virusscan_enterprise'
      ),
    "^1\.9\.0", make_array(
      'eol_date', 'December 31 2016',
      'kb', 'https://kc.mcafee.com/corporate/index?page=content&id=KB86212'
      ),
    "^1\.9\.1", make_array(
      'eol_date', 'December 31 2017',
      'kb', 'https://kc.mcafee.com/corporate/index?page=content&id=KB86212'
      ),
    "^1\.9\.[2-9]", make_array(
      'eol_date', 'December 31 2021',
      'kb', 'https://kc.mcafee.com/corporate/index?page=content&id=KB93335'
      ),
    "^2\.0\.[0-1]", make_array(
      'eol_date', 'December 31 2016',
      'kb', 'https://kc.mcafee.com/corporate/index?page=content&id=KB86212'
      ),
    "^2\.0\.2", make_array(
      'eol_date', 'December 31 2017',
      'kb', 'https://kc.mcafee.com/corporate/index?page=content&id=KB86212'
      ),
    "^2\.0\.3", make_array(
      'eol_date', 'December 31 2021',
      'kb', 'https://kc.mcafee.com/corporate/index?page=content&id=KB86212'
      ),
    "^2\.[0-9]\.[4-9]", make_array(
      'eol_date', 'December 31 2021',
      'kb', 'https://kc.mcafee.com/corporate/index?page=content&id=KB93335'
      )
    );

var eol, report;

foreach eol (keys(eol_versions))
{
  if (preg(pattern:eol, string:version))
  {
    register_unsupported_product(
      product_name:app_name, 
      cpe_base:"mcafee:virusscan_enterprise", 
      version:version);

    report =
    '\n  Product           : ' + app_name +
    '\n  Installed version : ' + version +
    '\n  End of life date  : ' + eol_versions[eol]['eol_date'] +
    '\n  EOL announcement  : ' + eol_versions[eol]['kb'] +
    '\n';
    security_report_v4(severity:SECURITY_HOLE, extra:report, port:0);
    exit(0);
  }
}
# If no audit/report by this point, version > latest unsupported.
exit(0, app_name + " " + version + " is still a supported version.");
