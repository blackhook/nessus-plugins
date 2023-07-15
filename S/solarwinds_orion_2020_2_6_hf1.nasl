#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154339);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

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

  script_name(english:"SolarWinds Orion Platform < 2020.2.6 HF1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of SolarWinds Orion Platform is prior to 2020.2.6 HF1. It is,
therefore, affected by multiple vulnerabilities:

  - A command injection vulnerability in the EmailWebPage API. An authenticated,
    remote attacker can exploit this to execute arbitrary
    commands.(CVE-2021-35220)
  
  - An arbitrary file read vulnerability in ExportToPdfCmd. An authenticated,
    remote attacker can exploit this to read arbitrary files and disclose
    sensitive information. (CVE-2021-35219)
  
  - An improper access control tampering vulnerability. An authenticated, remote
    attacker can exploit this to add arbitrary SMTP servers to the server
    configuration. (CVE-2021-35221)
  
  - Multiple stored cross-site scripting vulnerabilities. A cross-site scripting
    (XSS) vulnerability exists due to improper validation of user-supplied input
    before returning it to users. An unauthenticated, remote attacker can exploit
    this, by convincing a user visit a URL, to execute arbitrary script code in a
    user's browser session. (CVE-2021-35238, CVE-2021-35239, CVE-2021-35240)
  
  - A reflected cross-site scripting vulnerability. A cross-site scripting (XSS)
    vulnerability exists due to improper validation of user-supplied input before
    returning it to users. An unauthenticated, remote attacker can exploit this,
    by convincing a user to click a specially crafted URL, to execute arbitrary
    script code in a user's browser session. (CVE-2021-35222)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://support.solarwinds.com/SuccessCenter/s/article/Orion-Platform-2020-2-6-Hotfix-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c68109e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SolarWinds Orion Platform 2020.2.6 HF1 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35220");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-35222");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/22");

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

# Solarwinds documents describing the CVEs fixed in this version indicate 'Orion Platform 2020.2.5 and earlier' is affected
#  https://www.solarwinds.com/trust-center/security-advisories/cve-2021-35239
# Consulting the linked workaround indicates 2020.2.6 and earlier are affected.
# Since all the CVEs were addressed in only a '2020.2.6 HF1' update and most, if not all, also affect 2020.2.6 we are including it here.
var constraints = [{'fixed_version': '2020.2.6 HF1'}];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING, 
  flags:{xss:TRUE}
);
