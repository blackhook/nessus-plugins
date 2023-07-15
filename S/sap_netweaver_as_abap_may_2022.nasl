##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161186);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id("CVE-2022-28215", "CVE-2022-29610", "CVE-2022-29611");
  script_xref(name:"IAVA", value:"2022-A-0192-S");
  script_xref(name:"IAVA", value:"2022-A-0269");
  script_xref(name:"IAVA", value:"2022-A-0360");

  script_name(english:"SAP NetWeaver AS ABAP Multiple Vulnerabilities (January 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver ABAP server may be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Multiple vulnerabilities may be present in SAP NetWeaver Application Server ABAP, including the following:

  - A URL redirection vulnerability exists in SAP NetWeaver Application Server ABAP, due to insufficient URL
    validation. An unauthenticated, remote attacker can exploit this to redirect users to a malicious site and
    trick users to disxlose personal information. (CVE-2022-28215)

  - A cross-site scripting vulnerability exists in SAP NetWeaver Application Server ABAP. An authenticated,
    remote attacker can exploit this, by uploading malicious files and delete theme data, to execute arbitrary
    script code in a user's browser session. (CVE-2022-29610)

  - A privilege escalation vulnerability exists in SAP NetWeaver Application Server ABAP due to a missing
    authorization check. An authenticated, remote attacker can exploit this, to cause the contents of ABAP
    list output to be sent from the System Menu of the SAP Business System via e-mail without the appropriate
    authorization check. (CVE-2022-29611)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://securitybridge.com/sap-patchday/sap-security-patch-day-may-2022-2/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83816031");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3146336");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3165333");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3165801");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29611");

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
  {'equal' : '787', 'fixed_display' : fix },
  {'equal' : '788', 'fixed_display' : fix }
];

vcf::sap_netweaver_as::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  abap:TRUE,
  flags:{'xss':TRUE}
);
