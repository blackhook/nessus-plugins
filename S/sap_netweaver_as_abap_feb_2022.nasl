#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158042);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/20");

  script_cve_id("CVE-2022-22534", "CVE-2022-22540", "CVE-2022-22545");
  script_xref(name:"IAVA", value:"2022-A-0063");
  script_xref(name:"IAVA", value:"2022-A-0104");
  script_xref(name:"IAVA", value:"2022-A-0192-S");

  script_name(english:"SAP NetWeaver AS ABAP Multiple Vulnerabilities (Feb 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver ABAP server may be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Multiple vulnerabilities may be present in SAP NetWeaver Application Server ABAP, including the following:

  - SAP Netweaver AS - versions 700, 701, 702, 710, 711, 730, 740, 750, 751, 752, 753, 754, 755, 756 - contain
    a cross-site scripting vulnerability that allows an unauthenticated attacker to inject code that may expose
    sensitive data. (CVE-2022-22534)

  - SAP NetWeaver AS ABAP (Workplace Server) - versions 700, 701, 702, 731, 740 750, 751, 752, 753, 754, 755,
    756, 787 - contain a SQL injection vulnerability that allows an attacker to execute crafted database
    queries that could expose the backend database. (CVE-2022-22540)

  - SAP NetWeaver AS ABAP - versions 700, 701, 702, 710, 711, 730, 731, 740, 750, 751, 752, 753, 754, 755, 756 - 
    contain an information disclosure vulnerability that aloows an authenticated attacker to read connection
    details stored with the destination for http calls. (CVE-2022-22545) 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://wiki.scn.sap.com/wiki/display/PSR/SAP+Security+Patch+Day+-+February+2022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c6b4819");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3124994");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3140587");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3128473");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22540");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver_application_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'equal' : '711', 'fixed_display' : fix },
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
    {'equal' : '787', 'fixed_display' : fix }
  ];

vcf::sap_netweaver_as::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  abap:TRUE
);
