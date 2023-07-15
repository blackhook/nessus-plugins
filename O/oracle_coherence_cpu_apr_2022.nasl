#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159966);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id("CVE-2021-37137", "CVE-2021-43797", "CVE-2022-21420");
  script_xref(name:"IAVA", value:"2022-A-0171");

  script_name(english:"Oracle Coherence (Apr 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 12.2.1.3.0, 12.2.1.4.0, and 14.1.1.0.0 versions of Coherence installed on the remote host are affected by multiple
vulnerabilities as referenced in the April 2022 CPU advisory.

  - Vulnerability in the Oracle Coherence product of Oracle Fusion Middleware (component: Core). Supported
    versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via T3 to compromise Oracle Coherence. Successful
    attacks of this vulnerability can result in takeover of Oracle Coherence. (CVE-2022-21420)

  - Vulnerability in the PeopleSoft Enterprise PeopleTools product of Oracle PeopleSoft (component: Elastic
    Search (Netty)). Supported versions that are affected are 8.58 and 8.59. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via HTTP to compromise PeopleSoft Enterprise
    PeopleTools. Successful attacks require human interaction from a person other than the attacker.
    Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification
    access to critical data or all PeopleSoft Enterprise PeopleTools accessible data. (CVE-2021-43797)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21420");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:coherence");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_coherence_installed.nbin");
  script_require_keys("installed_sw/Oracle Coherence");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Coherence');

var constraints = [
  {'min_version': '12.2.1.3.0', 'fixed_version': '12.2.1.3.18'},
  {'min_version': '12.2.1.4.0', 'fixed_version': '12.2.1.4.13'},
  {'min_version': '14.1.1.0.0', 'fixed_version': '14.1.1.0.9'}
];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_HOLE
);
