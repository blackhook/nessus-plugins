#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154771);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-8088",
    "CVE-2018-10237",
    "CVE-2019-12400",
    "CVE-2020-7226",
    "CVE-2020-11022",
    "CVE-2021-29425",
    "CVE-2021-35552",
    "CVE-2021-35617",
    "CVE-2021-35620"
  );
  script_xref(name:"IAVA", value:"2021-A-0480");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle WebLogic Server Multiple Vulnerabilities (Oct 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0, and 14.1.1.0.0 versions of WebLogic Server installed on the remote
host are affected by multiple vulnerabilities as referenced in the October 2021 CPU advisory.

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Coherence
    Container). Supported versions that are affected are 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0.
    Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP to
    compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of
    Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).
    CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H). (CVE-2021-35617)

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Web Services
    (slf4j-ext)). The supported version that is affected is 12.1.3.0.0. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server.
    Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base
    Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H). (CVE-2018-8088)

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core).
    Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0.
    Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise
    Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete DOS) of Oracle WebLogic Server. CVSS 3.1 Base Score
    7.5 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-35620)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuoct2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2021 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35617");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_weblogic_server_installed.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Oracle WebLogic Server");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_weblogic::get_app_info();

var constraints = [
  {'min_version' : '14.1.1.0', 'fixed_version' : '14.1.1.0.210930', 'fixed_display' : '33416881 or 33452377'},
  {'min_version' : '12.2.1.4', 'fixed_version' : '12.2.1.4.210930', 'fixed_display' : '33416868 or 33455144'},
  {'min_version' : '12.2.1.3', 'fixed_version' : '12.2.1.3.210929', 'fixed_display' : '33452370 or 33412599'},
  {'min_version' : '12.1.3.0', 'fixed_version' : '12.1.3.0.211019', 'fixed_display' : '33172866'},
  {'min_version' : '10.3.6',   'fixed_version' : '10.3.6.0.211019', 'fixed_display' : '33172858'}
];

vcf::oracle_weblogic::check_version_and_report(app_info:app_info, severity:SECURITY_HOLE, constraints:constraints);