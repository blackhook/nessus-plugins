#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157127);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-1324",
    "CVE-2019-10219",
    "CVE-2020-2934",
    "CVE-2020-5258",
    "CVE-2020-11023",
    "CVE-2020-13956",
    "CVE-2021-4104",
    "CVE-2021-27568",
    "CVE-2021-29425",
    "CVE-2021-44832",
    "CVE-2022-21252",
    "CVE-2022-21257",
    "CVE-2022-21258",
    "CVE-2022-21259",
    "CVE-2022-21260",
    "CVE-2022-21261",
    "CVE-2022-21262",
    "CVE-2022-21292",
    "CVE-2022-21306",
    "CVE-2022-21347",
    "CVE-2022-21350",
    "CVE-2022-21353",
    "CVE-2022-21361",
    "CVE-2022-21371",
    "CVE-2022-21386"
  );
  script_xref(name:"IAVA", value:"2022-A-0029");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle WebLogic Server (Jan 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0, and 14.1.1.0.0 versions of WebLogic Server installed on the remote host are
affected by multiple vulnerabilities as referenced in the January 2022 CPU advisory.

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core).
    Supported versions that are affected are 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle
    WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic
    Server. (CVE-2022-21306)

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Web
    Container). Supported versions that are affected are 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0.
    Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to
    compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized
    access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base
    Score 7.5 (Confidentiality impacts). (CVE-2022-21371)

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Samples).
    Supported versions that are affected are 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server.
    Successful attacks of this vulnerability can result in unauthorized access to critical data or complete
    access to all Oracle WebLogic Server accessible data. (CVE-2022-21292)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44832");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_weblogic_server_installed.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Oracle WebLogic Server");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_weblogic::get_app_info();

var constraints = [
  {'min_version' : '14.1.1.0', 'fixed_version' : '14.1.1.0.220105', 'fixed_display' : '33727619 or 33751244'},
  {'min_version' : '12.2.1.4', 'fixed_version' : '12.2.1.4.220105', 'fixed_display' : '33751264 or 33727616'},
  {'min_version' : '12.2.1.3', 'fixed_version' : '12.2.1.3.211222', 'fixed_display' : '33699205 or 33751288'},
  {'min_version' : '12.1.3.0', 'fixed_version' : '12.1.3.0.220118', 'fixed_display' : '33494824 or later'}
];

vcf::oracle_weblogic::check_version_and_report(app_info:app_info, severity:SECURITY_HOLE, constraints:constraints);
