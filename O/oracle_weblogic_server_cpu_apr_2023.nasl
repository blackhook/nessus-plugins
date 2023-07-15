#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174464);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id(
    "CVE-2020-25638",
    "CVE-2020-6950",
    "CVE-2021-22569",
    "CVE-2021-31684",
    "CVE-2021-36090",
    "CVE-2022-31160",
    "CVE-2022-40152",
    "CVE-2022-45685",
    "CVE-2023-21931",
    "CVE-2023-21956",
    "CVE-2023-21960",
    "CVE-2023-21964",
    "CVE-2023-21979",
    "CVE-2023-21996",
    "CVE-2023-24998"
  );

  script_name(english:"Oracle WebLogic Server (Apr 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebLogic Server installed on the remote host is missing a security patch from the April 2023
Critical Patch Update (CPU). It is, therefore, affected by multiple vulnerabilities, including:

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console
    (Apache Commons FileUpload)). Supported versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and
    14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP
    to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle WebLogic Server.
    (CVE-2023-24998)

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Samples
    (XStream)). Supported versions that are affected are 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic
    Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of Oracle WebLogic Server. (CVE-2022-40152)

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Third Party
    (Apache Commons Compress)). Supported versions that are affected are 12.2.1.4.0 and 14.1.1.0.0. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete DOS) of Oracle WebLogic Server. (CVE-2021-36090)

  Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25638");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-21979");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_weblogic_server_installed.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Oracle WebLogic Server");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_weblogic::get_app_info();

var constraints = [
  { 'min_version' : '12.2.1.3.0', 'fixed_version' : '12.2.1.3.230402', 'fixed_display' : '35247514' }, # WLS Stack Patch Bundle
  { 'min_version' : '12.2.1.4.0', 'fixed_version' : '12.2.1.4.230328', 'fixed_display' : '35226999 or 35233446' },
  { 'min_version' : '14.1.1.0.0', 'fixed_version' : '14.1.1.0.230328', 'fixed_display' : '35227385 or 35233478' }
];

vcf::oracle_weblogic::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
