#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151808);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id("CVE-2021-33678");
  script_xref(name:"IAVA", value:"2021-A-0310");

  script_name(english:"SAP NetWeaver AS ABAP Code Injection (3048657)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver server is affected by a code injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"A code injection vulnerability exists in SAP NetWeaver Application Server ABAP 
(Reconciliation Framework). ABAP Server and ABAP Platform may allow a high privileged attacker
to inject code that can be executed by the application. An attacker could potentially delete
critical information and make the SAP system completely unavailable.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3048657");
  # https://wiki.scn.sap.com/wiki/pages/viewpage.action?pageId=580617506
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39f0ff28");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33678");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver_application_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sap_netweaver_as_web_detect.nbin");
  script_require_keys("installed_sw/SAP Netweaver Application Server (AS)", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443, 8000, 50000);

  exit(0);
}

include('vcf_extras_sap.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var app_info = vcf::sap_netweaver_as::get_app_info();

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
    {'equal' : '75A', 'fixed_display' : fix },
    {'equal' : '75B', 'fixed_display' : fix },
    {'equal' : '75C', 'fixed_display' : fix },
    {'equal' : '75D', 'fixed_display' : fix },
    {'equal' : '75E', 'fixed_display' : fix },
    {'equal' : '75F', 'fixed_display' : fix }
  ];

  vcf::sap_netweaver_as::check_version_and_report(app_info:app_info, 
                                                  constraints:constraints, 
                                                  severity:SECURITY_HOLE, 
                                                  abap:TRUE);