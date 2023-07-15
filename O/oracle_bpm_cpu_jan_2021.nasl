#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(145246);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-10173", "CVE-2020-10683", "CVE-2020-13935");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Business Process Management Suite (Jan 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Process Management Suite installed on the remote host is affected by the following
vulnerabilities as referenced in the January 2021 CPU advisory:

  - An XML External Entity (XXE) vulnerability exists in the dom4j library which allows DTDs and external
    entities by default. An unauthenticated, remote attacker can exploit this issue, to compromise the server.
    Successful attacks of this vulnerability can result in takeover of Oracle Business Process Management
    Suite. (CVE-2020-10683)

  - A deserialization flaw exists in the Oracle BAM (Business Activity Monitoring) product of Oracle
    Fusion Middleware (component: General (Xstream)) due to the introduction of a regression for a previous
    deserialization flaw. If the security framework has not been initialized, it may allow a remote attacker
    to run arbitrary shell commands when unmarshalling XML or any supported format. (CVE-2019-10173)

  - A denial of service (DoS) vulnerability exists in the Oracle Managed File Transfer product of Oracle
    Fusion Middleware (component: MFT Runtime Server (Apache Tomcat)) due to improper validation of the 
    payload length in a WebSocket frame. An unauthenticated, remote attacker can exploit this issue to
    trigger an infinite loop and cause a hang or frequently repeatable crash of Oracle Managed File Transfer.
    (CVE-2020-13935)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2021.html");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2021cvrf.xml");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2021 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10683");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_process_management_suite");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_bpm_installed.nbin");
  script_require_keys("installed_sw/Oracle Business Process Manager");

  exit(0);
}

include('vcf.inc');
app = 'Oracle Business Process Manager';
app_info = vcf::get_app_info(app:app);

constraints = [
  { 'min_version':'12.2.1.3.0', 'fixed_version' : '12.2.1.3.201210' },
  { 'min_version':'12.2.1.4.0', 'fixed_version' : '12.2.1.4.210102' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
