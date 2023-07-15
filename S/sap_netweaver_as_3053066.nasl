#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150718);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/17");

  script_cve_id("CVE-2021-27635");
  script_xref(name:"IAVA", value:"2021-A-0281");

  script_name(english:"SAP NetWeaver AS JAVA Missing XML Validation (3053066)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver AS Java server may be affected by a missing XML validation vulnerability.");
  script_set_attribute(attribute:"description", value:
"SAP Netweaver Application Server Java versions 7.20, 7.30, 7.31, 7.40, and 7.50 allow an attacker authenticated as an
administrator to connect over a network and submit a specially crafted XML file in the application because of missing
XML Validation. This vulnerability enables an attacker to fully compromise confidentiality by allowing them to read any
file on the filesystem or fully compromise availability by causing the system to crash. The attack cannot be used to
change any data so that there is no compromise as to integrity.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://wiki.scn.sap.com/wiki/pages/viewpage.action?pageId=578125999");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3053066");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27635");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/11");

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

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app_info = vcf::sap_netweaver_as::get_app_info();

var fix = 'See vendor advisory';
var constraints = [
  {'equal' : '7.20', 'fixed_display' : fix },
  {'equal' : '7.30', 'fixed_display' : fix },
  {'equal' : '7.31', 'fixed_display' : fix },
  {'equal' : '7.40', 'fixed_display' : fix },
  {'equal' : '7.50', 'fixed_display' : fix }
];

vcf::sap_netweaver_as::check_version_and_report(app_info:app_info, 
                                                  constraints:constraints, 
                                                  severity:SECURITY_WARNING, 
                                                  abap:FALSE);
