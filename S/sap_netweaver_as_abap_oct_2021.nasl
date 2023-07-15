#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154141);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/19");

  script_cve_id(
    "CVE-2021-38178",
    "CVE-2021-38181",
    "CVE-2021-40495",
    "CVE-2021-40496"
  );
  script_xref(name:"IAVA", value:"2021-A-0462");

  script_name(english:"SAP NetWeaver AS ABAP Multiple Vulnerabilities (Oct 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver ABAP server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Multiple vulnerabilities may be present in SAP NetWeaver Application Server ABAP, including the following:

  - SAP NetWeaver AS ABAP and ABAP Platform - versions 700, 701, 702, 730, 731, 740, 750, 751, 752, 753, 754,
    755, 756, allows an attacker to prevent legitimate users from accessing a service, either by crashing or
    flooding the service. (CVE-2021-38181)

  - There are multiple Denial-of Service vulnerabilities in SAP NetWeaver Application Server for ABAP and ABAP
    Platform - versions 740, 750, 751, 752, 753, 754, 755. An unauthorized attacker can use the public SICF
    service /sap/public/bc/abap to reduce the performance of SAP NetWeaver Application Server ABAP and ABAP
    Platform. (CVE-2021-40495)

  - SAP Internet Communication framework (ICM) - versions 700, 701, 702, 730, 731, 740, 750, 751, 752, 753,
    754, 755, 756, 785, allows an attacker with logon functionality, to exploit the authentication function
    by using POST and form field to repeat executions of the initial command by a GET request and exposing
    sensitive data. This vulnerability is normally exposed over the network and successful exploitation can
    lead to exposure of data like system details. (CVE-2021-40496)

  - The software logistics system of SAP NetWeaver AS ABAP and ABAP Platform versions - 700, 701, 702, 710,
    730, 731, 740, 750, 751, 752, 753, 754, 755, 756, enables a malicious user to transfer ABAP code artifacts
    or content, by-passing the established quality gates. By this vulnerability malicious code can reach
    quality and production, and can compromise the confidentiality, integrity, and availability of the system
    and its data. (CVE-2021-38178)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://wiki.scn.sap.com/wiki/pages/viewpage.action?pageId=587169983");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3097887");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3080710");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3099011");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3087254");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38178");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver_application_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sap_netweaver_as_web_detect.nbin");
  script_require_keys("installed_sw/SAP Netweaver Application Server (AS)", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443, 8000, 50000);

  exit(0);
}

include('vcf_extras_sap.inc');

var app_info = vcf::sap_netweaver_as::get_app_info();

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var fix = 'See vendor advisory';
var constraints = [
    {'equal' : '700', 'fixed_display' : fix },
    {'equal' : '701', 'fixed_display' : fix },
    {'equal' : '702', 'fixed_display' : fix },
    {'equal' : '710', 'fixed_display' : fix },
    {'equal' : '730', 'fixed_display' : fix },
    {'equal' : '731', 'fixed_display' : fix },
    {'equal' : '740', 'fixed_display' : fix },
    {'equal' : '750', 'fixed_display' : fix },
    {'equal' : '751', 'fixed_display' : fix },
    {'equal' : '752', 'fixed_display' : fix },
    {'equal' : '753', 'fixed_display' : fix },
    {'equal' : '754', 'fixed_display' : fix },
    {'equal' : '755', 'fixed_display' : fix },
    {'equal' : '756', 'fixed_display' : fix },
    {'equal' : '785', 'fixed_display' : fix }
  ];

vcf::sap_netweaver_as::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  abap:TRUE
);
