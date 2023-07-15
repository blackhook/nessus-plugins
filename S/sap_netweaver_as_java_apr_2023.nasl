#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174400);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/17");

  script_cve_id("CVE-2023-24527", "CVE-2022-41272");
  script_xref(name:"IAVA", value:"2023-A-0192");

  script_name(english:"SAP NetWeaver AS Java Multiple Vulnerabilities (April 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver application server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"SAP NetWeaver Application Server for Java is affected by multiple vulnerabilities, including the
following:

  - SAP NetWeaver AS Java for Deploy Service - version 7.5, does not perform any access control checks for 
    functionalities that require user identity enabling an unauthenticated attacker to attach to an open interface and 
    make use of an open naming and directory API to access a service which will enable them to access but not modify 
    server settings and data with no effect on availability and integrity. (CVE-2023-24527)

  - An unauthenticated attacker over the network can attach to an open interface exposed through JNDI by the User 
    Defined Search (UDS) of SAP NetWeaver Process Integration (PI) - version 7.50 and make use of an open naming and 
    directory API to access services which can be used to perform unauthorized operations affecting users and data 
    across the entire system. This allows the attacker to have full read access to user data, make limited 
    modifications to user data, and degrade the performance of the system, leading to a high impact on confidentiality 
    and a limited impact on the availability and integrity of the application. (CVE-2022-41272)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.sap.com/documents/2022/02/fa865ea4-167e-0010-bca6-c68f7e60039b.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18f404d5");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3273480");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3287784");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41272");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/17");

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
