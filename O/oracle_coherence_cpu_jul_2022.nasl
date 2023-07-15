##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163401);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id("CVE-2020-36518", "CVE-2022-21570");
  script_xref(name:"IAVA", value:"2022-A-0285");

  script_name(english:"Oracle Coherence (Jul 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 3.7.1.0, 12.2.1.3.0, 12.2.1.4.0, and 14.1.1.0.0 versions of Coherence installed on the remote host are affected
by multiple vulnerabilities as referenced in the July 2022 CPU advisory.

  - Vulnerability in the Oracle Coherence product of Oracle Fusion Middleware (component: Core). Supported
    versions that are affected are 3.7.1.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle
    Coherence. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of Oracle Coherence. (CVE-2022-21570)

  - Vulnerability in the Oracle Coherence product of Oracle Fusion Middleware (component: Centralized
    Thirdparty Jars (jackson-databind)). The supported version that is affected is 14.1.1.0.0. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Oracle Coherence. Successful attacks of this vulnerability can result in unauthorized ability to cause
    a hang or frequently repeatable crash (complete DOS) of Oracle Coherence. (CVE-2020-36518)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36518");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/22");

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
  {'min_version': '3.7.1.0', 'max_version': '3.7.1.999999', 'fixed_display': 'See vendor advisory'},
  {'min_version': '12.2.1.3.0', 'fixed_version': '12.2.1.3.19'},
  {'min_version': '12.2.1.4.0', 'fixed_version': '12.2.1.4.14'},
  {'min_version': '14.1.1.0.0', 'fixed_version': '14.1.1.0.10'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
