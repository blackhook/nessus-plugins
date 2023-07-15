##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163283);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id(
    "CVE-2022-21540",
    "CVE-2022-21541",
    "CVE-2022-21549",
    "CVE-2022-34169"
  );
  script_xref(name:"IAVA", value:"2022-A-0287-S");

  script_name(english:"Amazon Corretto Java 17.x < 17.0.4.8.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"Amazon Corretto is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Amazon Corretto installed on the remote host is prior to 17 < 17.0.4.8.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the corretto-17-2022-Jul-19 advisory.

  - hotspot/compiler (CVE-2022-21540)

  - hotspot/runtime (CVE-2022-21541)

  - core-libs/java.util (CVE-2022-21549)

  - xml/jaxp (CVE-2022-34169)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://github.com/corretto/corretto-17/blob/develop/CHANGELOG.md#corretto-version-170481
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be5dfd41");
  script_set_attribute(attribute:"solution", value:
"Update to Amazon Corretto Java 17.0.4.8.1 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34169");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/20");

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
  { 'min_version' : '17.0', 'fixed_version' : '17.0.4.8.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
