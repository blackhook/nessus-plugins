#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169455);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/17");

  script_cve_id("CVE-2022-41262");
  script_xref(name:"IAVA", value:"2022-A-0516");
  script_xref(name:"IAVA", value:"2023-A-0076");

  script_name(english:"SAP NetWeaver AS Java XSS (3262544)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver AS Java server may be affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"Due to insufficient input validation, SAP NetWeaver AS Java (HTTP Provider Service) - version 7.50, allows an 
unauthenticated attacker to inject a script into a web request header. On successful exploitation, an attacker can view
or modify information causing a limited impact on the confidentiality and integrity of the application.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.sap.com/documents/2022/02/fa865ea4-167e-0010-bca6-c68f7e60039b.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18f404d5");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41262");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/03");

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

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app_info = vcf::sap_netweaver_as::get_app_info();

var constraints = [
  {'equal' : '7.50', 'fixed_display' : 'See vendor advisory' }
];

vcf::sap_netweaver_as::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE}
);
