#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172603);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/18");

  script_cve_id(
    "CVE-2023-23857",
    "CVE-2023-24526", 
    "CVE-2023-26460", 
    "CVE-2023-27268");
  script_xref(name:"IAVA", value:"2023-A-0130");

  script_name(english:"SAP NetWeaver AS Java Multiple Vulnerabilities (March 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver application server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"SAP NetWeaver Application Server for Java is affected by multiple vulnerabilities, including the
following:

  - Due to missing authentication check, SAP NetWeaver AS for Java - version 7.50, allows an unauthenticated attacker 
    to attach to an open interface and make use of an open naming and directory API to access services which can be 
    used to perform unauthorized operations affecting users and services across systems. On a successful exploitation, 
    the attacker can read and modify some sensitive information but can also be used to lock up any element or 
    operation of the system making that it unresponsive or unavailable.(CVE-2023-23857)

  - SAP NetWeaver Application Server Java for Classload Service - version 7.50, does not perform any authentication 
    checks for functionalities that require user identity, resulting in escalation of privileges. This failure has a 
    low impact on confidentiality of the data such that an unassigned user can read non-sensitive server data. 
    (CVE-2023-24526)

  - Cache Management Service in SAP NetWeaver Application Server for Java - version 7.50, does not perform any 
    authentication checks for functionalities that require user identity. (CVE-2023-26460)

  - SAP NetWeaver AS Java (Object Analyzing Service) - version 7.50, does not perform necessary authorization checks, 
    allowing an unauthenticated attacker to attach to an open interface and make use of an open naming and directory 
    API to access a service which will enable them to access but not modify server settings and data with no effect on 
    availability., resulting in escalation of privileges. (CVE-2023-27268)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.sap.com/documents/2022/02/fa865ea4-167e-0010-bca6-c68f7e60039b.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18f404d5");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3252433");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3288480");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3288096");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3288394");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23857");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver_application_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sap_netweaver_as_web_detect.nbin");
  script_require_keys("installed_sw/SAP Netweaver Application Server (AS)", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443, 8000, 50000);

  exit(0);
}

include('vcf_extras_sap.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app_info = vcf::sap_netweaver_as::get_app_info();

var constraints = [
  {'equal' : '7.50', 'fixed_display' : 'See vendor advisory' }
];

vcf::sap_netweaver_as::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
