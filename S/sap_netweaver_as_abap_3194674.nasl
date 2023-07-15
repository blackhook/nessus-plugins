#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164820);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-29612");
  script_xref(name:"IAVA", value:"2022-A-0234");

  script_name(english:"SAP NetWeaver AS ABAP SSRF (3194674)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver server is affected by an server side request forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"A server side request forgery vulnerability exists in SAP NetWeaver Application Server ABAP. This allows an 
authenticated user to misuse a function of sapcontrol webfunctionality(startservice) in Kernel which enables malicious
users to retrieve information. On successful exploitation, an attacker can obtain technical information like system 
number or physical address, which is otherwise restricted, causing a limited impact on the confidentiality of the 
application.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3194674");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29612");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/07");

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

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var app_info = vcf::sap_netweaver_as::get_app_info();

var fix = 'See vendor advisory';
var constraints = [
    {'equal' : '722', 'fixed_display' : fix },
    {'equal' : '749', 'fixed_display' : fix },
    {'equal' : '753', 'fixed_display' : fix },
    {'equal' : '777', 'fixed_display' : fix },
    {'equal' : '781', 'fixed_display' : fix },
    {'equal' : '785', 'fixed_display' : fix },
    {'equal' : '786', 'fixed_display' : fix },
    {'equal' : '787', 'fixed_display' : fix },
    {'equal' : '788', 'fixed_display' : fix },
    {'equal' : '804', 'fixed_display' : fix }
  ];

vcf::sap_netweaver_as::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING, 
  abap:TRUE);