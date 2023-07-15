#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167283);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/12");

  script_cve_id("CVE-2022-41212", "CVE-2022-41214");
  script_xref(name:"IAVA", value:"2022-A-0469");

  script_name(english:"SAP NetWeaver AS ABAP Multiple Vulnerabilities (3256571)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver ABAP server may be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Multiple vulnerabilities may be present in SAP NetWeaver Application Server ABAP, including the following:

  - Due to insufficient input validation, SAP NetWeaver Application Server ABAP and ABAP Platform allows an
    attacker with high level privileges to use a remote enabled function to delete a file which is otherwise
    restricted. On successful exploitation an attacker can completely compromise the integrity and availability
    of the application. (CVE-2022-41214)

  - Due to insufficient input validation, SAP NetWeaver Application Server ABAP and ABAP Platform allows an
    attacker with high level privileges to use a remote enabled function to read a file which is otherwise
    restricted. On successful exploitation an attacker can completely compromise the confidentiality of the
    application. (CVE-2022-41212)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.sap.com/documents/2022/02/fa865ea4-167e-0010-bca6-c68f7e60039b.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18f404d5");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3256571");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41214");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver_application_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sap_netweaver_as_web_detect.nbin");
  script_require_keys("installed_sw/SAP Netweaver Application Server (AS)");
  script_require_ports("Services/www", 80, 443, 8000, 50000);

  exit(0);
}

include('vcf_extras_sap.inc');

var app_info = vcf::sap_netweaver_as::get_app_info();

if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN);

var fix = 'See vendor advisory';
var constraints = [
    {'min_version' : '700', 'max_version' : '702', 'fixed_display' : fix },
    {'equal' : '731', 'fixed_display' : fix },
    {'equal' : '740', 'fixed_display' : fix },
    {'min_version' : '750', 'max_version' : '757' ,'fixed_display' : fix },
    {'min_version' : '789', 'max_version' : '790' ,'fixed_display' : fix },
    {'equal' : '804', 'fixed_display' : fix }
  ];

vcf::sap_netweaver_as::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  abap:TRUE
);
