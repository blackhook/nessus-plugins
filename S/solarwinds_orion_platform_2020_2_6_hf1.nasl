#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155443);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id(
    "CVE-2021-35219",
    "CVE-2021-35220",
    "CVE-2021-35221",
    "CVE-2021-35222",
    "CVE-2021-35238",
    "CVE-2021-35239",
    "CVE-2021-35240"
  );
  script_xref(name:"IAVA", value:"2021-A-0477-S");

  script_name(english:"SolarWinds Orion Platform 2020.2.0 < 2020.2.6 HF1 Multiple Vulnerabilities XSS");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The version of SolarWinds Orion Platform installed on the remote host is prior to 2020.2.6 HF1. It is, therefore,
affected by multiple vulnerabilities as referenced in the orion_platform_2020_2_6_hf1 advisory.

  - A security researcher found a user with Orion map manage rights could store XSS through via text box
    hyperlink. (CVE-2021-35239)

  - A security researcher stored XSS via a Help Server setting. This affects customers using Internet
    Explorer, because they do not support 'rel=noopener'. (CVE-2021-35240)

  - Improper Access Control Tampering Vulnerability using ImportAlert function which can lead to a Remote Code
    Execution (RCE) from the Alerts Settings page. (CVE-2021-35221)

  - User with Orion Platform Admin Rights could store XSS through URL POST parameter in CreateExternalWebsite
    website. (CVE-2021-35238)

  - ExportToPdfCmd Arbitrary File Read Information Disclosure Vulnerability using ImportAlert function within
    the Alerts Settings page. (CVE-2021-35219)

  - This vulnerability allows attackers to impersonate users and perform arbitrary actions leading to a Remote
    Code Execution (RCE) from the Alerts Settings page. (CVE-2021-35222)

  - Command Injection vulnerability in EmailWebPage API which can lead to a Remote Code Execution (RCE) from
    the Alerts Settings page. (CVE-2021-35220)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2021-35239
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?087598e5");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2021-35240
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?175110db");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2021-35221
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1b56a48");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2021-35238
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d718ba97");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2021-35219
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?501061de");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2021-35222
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9362f652");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2021-35220
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e159524");
  script_set_attribute(attribute:"solution", value:
"");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35220");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-35222");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_platform");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solarwinds_orion_npm_detect.nasl", "solarwinds_orion_installed.nbin");
  script_require_keys("installed_sw/SolarWinds Orion Core");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::solarwinds_orion::initialize();
var app_info = vcf::solarwinds_orion::combined_get_app_info();

var constraints = [
  { 'min_version' : '2020.2.0', 'max_version' : '2020.2.5', 'fixed_version' : '2020.2.6 HF1' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
