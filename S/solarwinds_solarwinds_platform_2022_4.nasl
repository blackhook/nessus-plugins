#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166605);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/05");

  script_cve_id("CVE-2022-36960", "CVE-2022-36962", "CVE-2022-36964");
  script_xref(name:"IAVA", value:"2022-A-0441");
  script_xref(name:"IAVA", value:"2022-A-0500-S");

  script_name(english:"SolarWinds Orion Platform < 2022.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of SolarWinds Orion Platform installed on the remote host is prior to 2022.4. It is, therefore, affected 
by multiple vulnerabilities as referenced in the solarwinds_platform_2022_4 advisory:

  - SolarWinds Platform was susceptible to the Deserialization of Untrusted Data. This vulnerability allows a remote 
    adversary with valid access to SolarWinds Web Console to execute arbitrary commands. (CVE-2022-36958)

  - SolarWinds Platform was susceptible to the Deserialization of Untrusted Data. This vulnerability allows a remote 
    adversary with Orion admin-level account access to SolarWinds Web Console to execute arbitrary commands.
    (CVE-2022-36957)

  - SolarWinds Platform was susceptible to the Deserialization of Untrusted Data. This vulnerability allows a remote 
    adversary with Orion admin-level account access to SolarWinds Web Console to execute arbitrary commands. 
    (CVE-2022-38108)

  - Users with Node Management rights were able to view and edit all nodes due to Insufficient control on URL parameter 
    causing insecure direct object reference (IDOR) vulnerability in SolarWinds Platform 2022.3. (CVE-2022-36966)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://documentation.solarwinds.com/en/success_center/orionplatform/content/release_notes/solarwinds_platform_2022-4_release_notes.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea0c4b1f");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2022-36966
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e3c9d06");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2022-38108
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dbc9a8ac");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2022-36958
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c4d4bc0");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2022-36957
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?05234fd0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Orion Platform version 2022.4 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-36958");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_platform");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solarwinds_orion_npm_detect.nasl", "solarwinds_orion_installed.nbin");
  script_require_keys("installed_sw/SolarWinds Orion Core");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::solarwinds_orion::initialize();
var app_info = vcf::solarwinds_orion::combined_get_app_info();

var constraints = [
  { 'min_version' : '2022.0', 'fixed_version' : '2022.4', 'fixed_display' : '2022.4 RC1' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);