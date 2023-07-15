##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(174510);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2022-41881", "CVE-2022-42003");
  script_xref(name:"IAVA", value:"2023-A-0210");

  script_name(english:"Oracle Coherence (Apr 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 12.2.1.4.0 and 14.1.1.0.0 versions of Coherence installed on the remote host are affected by multiple
vulnerabilities as referenced in the April 2023 CPU advisory.

  - Vulnerability in the Netty component of Oracle Coherence 12.2.1.4.0 and 14.1.1.0.0. Netty component is an 
    event-driven asynchronous network application framework. In versions prior to 4.1.86.Final, a 
    StackOverflowError can be raised when parsing a malformed crafted message due to an  infinite recursion.
    (CVE-2022-41881)

  - Vulnerability in the jackson-databind component of Oracle Coherence 12.2.1.4.0 and 14.1.1.0.0. In FasterXML
    jackson-databind before 2.14.0-rc1, resource exhaustion can occur because of a lack of a check in primitive 
    value deserializers to avoid deep wrapper array nesting, when the UNWRAP_SINGLE_VALUE_ARRAYS feature is 
    enabled. (CVE-2022-42003)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42003");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:coherence");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_coherence_installed.nbin");
  script_require_keys("installed_sw/Oracle Coherence");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Coherence');

var constraints = [
  {'min_version': '12.2.1.4.0', 'fixed_version': '12.2.1.4.17'},
  {'min_version': '14.1.1.0.0', 'fixed_version': '14.1.1.0.13'}
];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_HOLE
);
