#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159402);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2019-13117",
    "CVE-2019-13118",
    "CVE-2019-16168",
    "CVE-2020-2583",
    "CVE-2020-2585",
    "CVE-2020-2590",
    "CVE-2020-2593",
    "CVE-2020-2601",
    "CVE-2020-2604",
    "CVE-2020-2654",
    "CVE-2020-2655",
    "CVE-2020-2659"
  );
  script_xref(name:"IAVA", value:"2020-A-0021-S");

  script_name(english:"Amazon Corretto Java 8.x < 8.242.07.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"Amazon Corretto is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Amazon Corretto installed on the remote host is prior to 8 < 8.242.07.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the corretto-8-2020-Jan-14 advisory.

  - OpenJFX (libxslt) (CVE-2019-13117, CVE-2019-13118)

  - OpenJFX (SQLite) (CVE-2019-16168)

  - Serialization (CVE-2020-2583, CVE-2020-2604)

  - OpenJFX (CVE-2020-2585)

  - Security (CVE-2020-2590, CVE-2020-2601)

  - Networking (CVE-2020-2593, CVE-2020-2659)

  - Libraries (CVE-2020-2654)

  - JSSE (CVE-2020-2655)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://github.com/corretto/corretto-8/blob/develop/CHANGELOG.md#corretto-version-8242071
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c34d25e7");
  script_set_attribute(attribute:"solution", value:
"Update to Amazon Corretto Java 8.242.07.1 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2604");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:amazon:corretto");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'min_version' : '8.0', 'fixed_version' : '8.242.07.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'sqli':TRUE}
);
