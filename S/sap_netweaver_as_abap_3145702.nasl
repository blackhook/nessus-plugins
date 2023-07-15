##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161185);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/20");

  script_cve_id("CVE-2022-29616");
  script_xref(name:"IAVA", value:"2022-A-0192-S");

  script_name(english:"SAP NetWeaver AS ABAP and AS Java Memory Corruption (3145702)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver AS Java server may be affected by a memory corruption vulnerability.");
  script_set_attribute(attribute:"description", value:
"A memory corruption vulnerability exists in SAP NetWeaver AS ABAP and AS Java kernel versions 7.22, 7.49, 7.53, 7.77,
7.81, 7.85, 7.86, 7.87, 7.88, and 8.04 which may allow an unauthenticated attacker to steal authentication information
of the user.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://securitybridge.com/sap-patchday/sap-security-patch-day-may-2022-2/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83816031");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3145702");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29616");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/13");

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

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Vuln is for ABAP and AS Java, but advisory only has kernel versions
var app_info = vcf::sap_netweaver_as::get_app_info(kernel:TRUE);

var constraints = [
  {'equal' : '7.22', 'fixed_display' : 'See vendor advisory' },
  {'equal' : '7.49', 'fixed_display' : 'See vendor advisory' },
  {'equal' : '7.53', 'fixed_display' : 'See vendor advisory' },
  {'equal' : '7.77', 'fixed_display' : 'See vendor advisory' },
  {'equal' : '7.81', 'fixed_display' : 'See vendor advisory' },
  {'equal' : '7.85', 'fixed_display' : 'See vendor advisory' },
  {'equal' : '7.86', 'fixed_display' : 'See vendor advisory' },
  {'equal' : '7.87', 'fixed_display' : 'See vendor advisory' },
  {'equal' : '7.88', 'fixed_display' : 'See vendor advisory' },
  {'equal' : '8.04', 'fixed_display' : 'See vendor advisory' }
];

vcf::sap_netweaver_as::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE},
  kernel:TRUE
);
