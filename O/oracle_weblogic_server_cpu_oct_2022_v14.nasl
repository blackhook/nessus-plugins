#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166314);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id(
    "CVE-2020-28052",
    "CVE-2021-29425",
    "CVE-2022-21616",
    "CVE-2022-22971",
    "CVE-2022-23437"
  );
  script_xref(name:"IAVA", value:"2022-A-0431");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle WebLogic Server 14.1.1 < 14.1.1.0.221010 (Oct 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebLogic Server installed on the remote host is missing a security patch from the October 2022
Critical Patch Update (CPU). It is, therefore, affected by multiple vulnerabilities, including:

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Centralized Thirdparty
    Jars (Bouncy Castle Java Library)). Supported versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via TLS to compromise Oracle
    WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server.
    (CVE-2020-28052)

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Centralized Thirdparty
    Jars (Apache Xerces-J)). Supported versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic
    Server. Successful attacks require human interaction from a person other than the attacker. Successful attacks of
    this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS)
    of Oracle WebLogic Server. (CVE-2022-23437)

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Web Container).
    Supported versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Difficult to exploit vulnerability
    allows high privileged attacker with logon to the infrastructure where Oracle WebLogic Server executes to
    compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete DOS) of Oracle WebLogic Server as well as unauthorized update,
    insert or delete access to some of Oracle WebLogic Server accessible data and unauthorized read access to a subset
    of Oracle WebLogic Server accessible data. (CVE-2022-21616)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28052");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/20");

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
  { 'min_version' : '14.1.1.0.0', 'fixed_version' : '14.1.1.0.221010', 'fixed_display' : '34686388 or 34693470' }
];

vcf::oracle_weblogic::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
