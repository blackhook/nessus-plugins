#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172604);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/20");

  script_cve_id(
    "CVE-2023-25618",
    "CVE-2023-26459",
    "CVE-2023-27269",
    "CVE-2023-27270",
    "CVE-2023-27500",
    "CVE-2023-27501"
  );
  script_xref(name:"IAVA", value:"2023-A-0130");

  script_name(english:"SAP NetWeaver AS ABAP Multiple Vulnerabilities (March 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver ABAP server may be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"SAP NetWeaver Application Server for ABAP and ABAP Platform is affected by multiple vulnerabilities, including the
following:

  - SAP NetWeaver Application Server for ABAP and ABAP Platform - versions 700, 701, 702, 731, 740, 750, 751, 752, 753,
    754, 755, 756, 757, 791, allows an attacker with non-administrative authorizations to exploit a directory traversal 
    flaw in an available service to overwrite the system files. In this attack, no data can be read but potentially 
    critical OS files can be overwritten making the system unavailable. (CVE-2023-27269)

  - An attacker with non-administrative authorizations can exploit a directory traversal flaw in program SAPRSBRO to 
    over-write system files. In this attack, no data can be read but potentially critical OS files can be over-written 
    making the system unavailable. (CVE-2023-27500)

  - SAP NetWeaver AS for ABAP and ABAP Platform - versions 700, 701, 702, 731, 740, 750, 751, 752, 753, 754, 755, 756, 
    757, 791, allows an attacker to exploit insufficient validation of path information provided by users, thus 
    exploiting a directory traversal flaw in an available service to delete system files. In this attack, no data can 
    be read but potentially critical OS files can be deleted making the system unavailable, causing significant impact 
    on both availability and integrity (CVE-2023-27501)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.sap.com/documents/2022/02/fa865ea4-167e-0010-bca6-c68f7e60039b.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18f404d5");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3296346");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3294595");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3296328");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3302162");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3294954");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-27501");

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

var app_info = vcf::sap_netweaver_as::get_app_info();

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var fix = 'See vendor advisory';
var constraints = [
    {'min_version' : '700', 'max_version' : '702', 'fixed_display' : fix },
    {'equal' : '731', 'fixed_display' : fix },
    {'equal' : '740', 'fixed_display' : fix },
    {'min_version' : '750', 'max_version' : '757', 'fixed_display' : fix },
    {'equal' : '791', 'fixed_display' : fix }
  ];

vcf::sap_netweaver_as::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  abap:TRUE
);
