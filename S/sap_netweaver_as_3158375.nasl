##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162396);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-27668");
  script_xref(name:"IAVA", value:"2022-A-0234");

  script_name(english:"SAP NetWeaver ABAP Improper Access Control (3158375)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver ABAP server may be affected by an improper access control vulnerability.");
  script_set_attribute(attribute:"description", value:
"Depending on the configuration of the route permission table in file 'saprouttab',  it is possible for an
unauthenticated attacker to execute SAProuter administration commands in SAP NetWeaver and ABAP Platform,
from a remote client, for example stopping the SAProuter, that could highly impact systems availability.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported
version number.");
  # https://www.sap.com/documents/2022/02/fa865ea4-167e-0010-bca6-c68f7e60039b.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18f404d5");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3158375");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27668");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver_application_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sap_netweaver_as_web_detect.nbin");
  script_require_keys("installed_sw/SAP Netweaver Application Server (AS)", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443, 8000, 50000);

  exit(0);
}

include('vcf_extras_sap.inc');

var app_info = vcf::sap_netweaver_as::get_app_info(kernel:TRUE);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var fix = 'See vendor advisory';
var  constraints = [
  {'equal' : '7.22', 'fixed_display' : 'See vendor advisory' },
  {'equal' : '7.49', 'fixed_display' : 'See vendor advisory' },
  {'equal' : '7.53', 'fixed_display' : 'See vendor advisory' },
  {'equal' : '7.77', 'fixed_display' : 'See vendor advisory' },
  {'equal' : '7.81', 'fixed_display' : 'See vendor advisory' },
  {'equal' : '7.85', 'fixed_display' : 'See vendor advisory' },
  {'equal' : '7.86', 'fixed_display' : 'See vendor advisory' },
  {'equal' : '7.87', 'fixed_display' : 'See vendor advisory' },
  {'equal' : '7.88', 'fixed_display' : 'See vendor advisory' }
];

vcf::sap_netweaver_as::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  kernel:TRUE,
  abap:TRUE
);
