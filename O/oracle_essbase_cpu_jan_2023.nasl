#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171320);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id(
    "CVE-2022-2068",
    "CVE-2022-2097",
    "CVE-2022-2274",
    "CVE-2022-42915",
    "CVE-2022-42916"
  );
  script_xref(name:"IAVA", value:"2023-A-0036-S");

  script_name(english:"Oracle Essbase (Jan 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A business analytics solution installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Essbase installed on the remote host is missing a security patch from the January 2023
Critical Patch Update (CPU). It is, therefore, affected by multiple vulnerabilities, including:

  - Vulnerability in Oracle Essbase (component: Essbase Web Platform (OpenSSL)). The supported version that is
    affected is 21.4. Easily exploitable vulnerability allows unauthenticated attacker with network access via
    HTTPS to compromise Oracle Essbase. Successful attacks of this vulnerability can result in takeover of
    Oracle Essbase. (CVE-2022-2274)

  - Vulnerability in Oracle Essbase (component: Infrastructure (cURL)). The supported version that is affected
    is 21.4. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to
    compromise Oracle Essbase. Successful attacks of this vulnerability can result in takeover of Oracle
    Essbase. (CVE-2022-42915)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2274");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-42915");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:essbase");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_essbase_installed.nbin");
  script_require_keys("installed_sw/Oracle Essbase");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Essbase');

var constraints = [
  { 'min_version' : '21.0.0.0', 'fixed_version' : '21.4.2.0', 'fixed_display' : '21.4.2.0 (Patch 34845421)'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
