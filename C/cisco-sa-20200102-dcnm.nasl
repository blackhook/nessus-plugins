#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132721);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-15975",
    "CVE-2019-15976",
    "CVE-2019-15977",
    "CVE-2019-15978",
    "CVE-2019-15979",
    "CVE-2019-15980",
    "CVE-2019-15981",
    "CVE-2019-15982",
    "CVE-2019-15983",
    "CVE-2019-15984",
    "CVE-2019-15985",
    "CVE-2019-15999"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq85945");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq85957");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq85972");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq85998");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq89422");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq89834");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq89841");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq89859");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq89878");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq89895");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq89898");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq98723");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq98730");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq98736");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq98748");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr01692");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr01694");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr01701");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr05463");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr07317");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr14598");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr17970");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr17974");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr23573");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr23728");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr23733");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr23770");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr23864");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr23865");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr32014");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr34624");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr44798");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr44896");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr46507");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr46508");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr46544");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr46547");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr79116");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr79127");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr79188");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr79240");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr88730");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr88737");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs00139");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs16306");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs16318");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs16341");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs16350");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200102-dcnm-auth-bypass");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200102-dcnm-sql-inject");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200102-dcnm-path-trav");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200102-dcnm-comm-inject");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200102-dcnm-xml-ext-entity");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200102-dcnm-unauth-access");
  script_xref(name:"IAVA", value:"2020-A-0009-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0004");
  script_xref(name:"CEA-ID", value:"CEA-2020-0003");

  script_name(english:"Cisco Data Center Network Manager < 11.3(1) Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Cisco DCNM hosted on the remote server is prior
to 11.3(1). It is, therefore, affected by multiple vulnerabilities:

  - An authentication bypass vulnerability exists in the REST API, SOAP API, and the web-based management
    interface due to a static encryption key being shared between installations. An unauthenticated, remote
    attacker can exploit this, via the REST API, SOAP API, or web-based management interface, to bypass
    authentication and execute arbitrary actions with administrative privileges. (CVE-2019-15975,
    CVE-2019-15976, CVE-2019-15977)

  - A command injection vulnerability exists in the REST API and SOAP API due to insufficient validation of
    user-supplied input. An authenticated, remote attacker can exploit this, via the APIs, to execute
    arbitrary commands. (CVE-2019-15978, CVE-2019-15979)

  - A path traversal vulnerability exists in the REST API and SOAP API due to insufficient validation of
    user-supplied input. An authenticated, remote attacker can exploit this, via the APIs, to read, write, or
    execute arbitrary files on the system. (CVE-2019-15980, CVE-2019-15981, CVE-2019-15982)

  - An XML external entity (XXE) vulnerability exists due to an incorrectly configured XML parser accepting
    XML external entities from an untrusted source. An authenticated, remote attacker can exploit this, via
    specially crafted XML data in the SOAP API, to disclose sensitive information. (CVE-2019-15983)

  - A SQL injection (SQLi) vulnerability exists in the SOAP API and REST API due to improper validation of
    user-supplied input. An authenticated, remote attacker can exploit this to inject or manipulate SQL
    queries in the back-end database, resulting in the disclosure or manipulation of arbitrary data.
    (CVE-2019-15984, CVE-2019-15985, CVE-2019-15986)

  - A vulnerability exists in the authentication settings of the JBOSS EAP due to an incorrect configuration.
    An authenticated, remote attacker can exploit this by authentication with a specific low-privilege
    account, to gain unauthorized access to the JBOSS EAP. (CVE-2019-15999)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200102-dcnm-auth-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7295287f");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200102-dcnm-sql-inject
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3a5bc15");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200102-dcnm-path-trav
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc0e4dd2");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200102-dcnm-comm-inject
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c51ba034");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200102-dcnm-xml-ext-entity
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?631a2bce");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200102-dcnm-unauth-access
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cd86400d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Data Center Network Manager version 11.3(1) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15976");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 78, 89, 284, 611, 798);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:data_center_network_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_dcnm_installed_win.nasl", "cisco_prime_dcnm_installed_linux.nasl", "cisco_prime_dcnm_web_detect.nasl");
  script_require_ports("installed_sw/Cisco Prime DCNM", "installed_sw/cisco_dcnm_web");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::cisco_dcnm_web::get_app_info();
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'fixed_version' : '11.3.1.0', 'fixed_display' : '11.3(1)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{xss:TRUE, sqli:TRUE});
