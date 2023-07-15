#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156226);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/12/22");

  script_cve_id("CVE-2021-44235");
  script_xref(name:"IAVA", value:"2021-A-0599");

  script_name(english:"SAP NetWeaver AS ABAP Code Injection (December 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver ABAP server is affected by code injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"A code injection vulnerability may be present in SAP NetWeaver Application Server ABAP. Two methods of a utility
class in SAP NetWeaver AS ABAP - versions 700, 701, 702, 710, 711, 730, 731, 740, 750, 751, 752, 753, 754, 755, 756,
allow an attacker with high privileges and has direct access to SAP System, to inject code when executing with a 
certain transaction class builder. This could allow execution of arbitrary commands on the operating system, that 
could highly impact the Confidentiality, Integrity and Availability of the system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://wiki.scn.sap.com/wiki/display/PSR/SAP+Security+Patch+Day+-+December+2021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e388843b");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3123196");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44235");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/21");

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
    {'equal' : '756', 'fixed_display' : fix }
  ];

vcf::sap_netweaver_as::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  abap:TRUE
);
