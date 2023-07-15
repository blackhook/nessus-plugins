#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159424);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-2745",
    "CVE-2019-2762",
    "CVE-2019-2766",
    "CVE-2019-2769",
    "CVE-2019-2786",
    "CVE-2019-2816",
    "CVE-2019-2842",
    "CVE-2019-7317"
  );
  script_xref(name:"IAVA", value:"2019-A-0164-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Amazon Corretto Java 8.x < 8.222.10.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"Amazon Corretto is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Amazon Corretto installed on the remote host is prior to 8 < 8.222.10.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the corretto-8-2019-Jul-16 advisory.

  - Security (CVE-2019-2745, CVE-2019-2786)

  - Utilities (CVE-2019-2762, CVE-2019-2769)

  - Networking (CVE-2019-2766, CVE-2019-2816)

  - JCE (CVE-2019-2842)

  - AWT (libpng) (CVE-2019-7317)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://github.com/corretto/corretto-8/blob/develop/CHANGELOG.md#july-2019-critical-patch-update-corretto-version-8222101
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0f77c73");
  script_set_attribute(attribute:"solution", value:
"Update to Amazon Corretto Java 8.222.10.1 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2816");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-2745");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/16");
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
  { 'min_version' : '8.0', 'fixed_version' : '8.222.10.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
