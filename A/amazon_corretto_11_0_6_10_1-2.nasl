#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159413);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Amazon Corretto Java 11.x < 11.0.6.10.1-2 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"Amazon Corretto is affected a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Amazon Corretto installed on the remote host is prior to 11 < 11.0.6.10.1-2. It is, therefore, affected
by a vulnerability as referenced in the corretto-11-2020-Jan-23 advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/corretto/corretto-11/blob/develop/CHANGELOG.md#corretto-version-1106101-2-macos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c2c22cad");
  script_set_attribute(attribute:"solution", value:
"Update to Amazon Corretto Java 11.0.6.10.1-2 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:amazon:corretto");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("amazon_corretto_win_installed.nbin", "amazon_corretto_nix_installed.nbin");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['Amazon Corretto Java'];
var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '11.0', 'fixed_version' : '11.0.6.10.1-2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
