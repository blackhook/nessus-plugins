##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161659);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id("CVE-2021-41032");
  script_xref(name:"IAVA", value:"2022-A-0221-S");

  script_name(english:"Fortinet FortiOS Access Control (FG-IR-21-147)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a access control vulnerability.");
  script_set_attribute(attribute:"description", value:
"An improper access control vulnerability in FortiOS versions 6.4.8 and prior and 7.0.3 and prior may allow an 
authenticated attacker with a restricted user profile to gather sensitive information and modify the SSL-VPN tunnel 
status of other VDOMs using specific CLI commands.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-21-147");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41032");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/version");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

var app_name = 'FortiOS';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');
vcf::fortios::verify_product_and_model(product_name:'FortiGate');

var constraints = [
  { 'min_version': '6.2', 'fixed_version' : '6.2.11' },
  { 'min_version': '6.4', 'fixed_version' : '6.4.9' },
  { 'min_version': '7.0', 'fixed_version' : '7.0.4' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);