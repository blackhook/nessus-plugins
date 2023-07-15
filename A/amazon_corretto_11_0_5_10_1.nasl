#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159435);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id(
    "CVE-2019-2894",
    "CVE-2019-2933",
    "CVE-2019-2945",
    "CVE-2019-2949",
    "CVE-2019-2958",
    "CVE-2019-2962",
    "CVE-2019-2964",
    "CVE-2019-2973",
    "CVE-2019-2975",
    "CVE-2019-2977",
    "CVE-2019-2978",
    "CVE-2019-2981",
    "CVE-2019-2983",
    "CVE-2019-2987",
    "CVE-2019-2988",
    "CVE-2019-2989",
    "CVE-2019-2992",
    "CVE-2019-2999"
  );
  script_xref(name:"IAVA", value:"2019-A-0385");

  script_name(english:"Amazon Corretto Java 11.x < 11.0.5.10.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"Amazon Corretto is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Amazon Corretto installed on the remote host is prior to 11 < 11.0.5.10.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the corretto-11-2019-Oct-15 advisory.

  - security-libs/javax.net.ssl (CVE-2019-2894, CVE-2019-2949)

  - core-libs (CVE-2019-2933)

  - core-libs/java.net (CVE-2019-2945, CVE-2019-2978, CVE-2019-2989)

  - core-libs/java.lang (CVE-2019-2958)

  - client-libs/2d (CVE-2019-2962, CVE-2019-2983, CVE-2019-2987, CVE-2019-2988, CVE-2019-2992)

  - core-libs/java.util.regex (CVE-2019-2964)

  - xml/jaxp (CVE-2019-2973, CVE-2019-2981)

  - core-libs/javax.script (CVE-2019-2975)

  - hotspot/compiler (CVE-2019-2977)

  - tools/javadoc (CVE-2019-2999)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://github.com/corretto/corretto-11/blob/develop/CHANGELOG.md#october-2019-critical-patch-update-corretto-version-1105101
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b0af98d6");
  script_set_attribute(attribute:"solution", value:
"Update to Amazon Corretto Java 11.0.5.10.1 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2977");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-2989");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/15");
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
  { 'min_version' : '11.0', 'fixed_version' : '11.0.5.10.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
