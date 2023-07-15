#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2022/04/12 
##

include('deprecated_nasl_level.inc');
include('compat.inc');
include('vcf.inc');
include('vcf_extras.inc');

if (description)
{
  script_id(159405);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/15");

  script_name(english:"Amazon Corretto Java 8.x < 8.322.06.3 Vulnerability (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"No security updates involved");
  # https://github.com/corretto/corretto-8/blob/develop/CHANGELOG.md#corretto-version-8322063
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c64afaf1");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/25");
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
exit(0, "This plugin has been deprecated.");

