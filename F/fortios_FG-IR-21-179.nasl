##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163262);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/08");

  script_cve_id("CVE-2021-44170");
  script_xref(name:"IAVA", value:"2022-A-0264-S");

  script_name(english:"Fortinet FortiOS Buffer Overflow (FG-IR-21-206)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS that is 6.0.x through 6.0.14, 6.2.x through 6.2.10, 6.4.x through
6.4.8, or 7.0.x through 7.0.2. It is, therefore, affected by a stack-based buffer overflow vulnerability. An
authenticated, remote attacker can exploit this issue, via specially crafted command line arguments, to execute
unauthorized code or commands.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-21-179");
  script_set_attribute(attribute:"solution", value:
"Update FortiOS to version 6.2.11, 6.4.9, 7.0.4, or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44170");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

var app_name = 'FortiOS';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

var constraints = [
  { 'min_version': '6.0', 'max_version' : '6.0.14', 'fixed_display' : '6.2.11 / 6.4.9 / 7.0.4' },
  { 'min_version': '6.2', 'fixed_version' : '6.2.11' },
  { 'min_version': '6.4', 'fixed_version' : '6.4.9' },
  { 'min_version': '7.0', 'max_version' : '7.0.2', 'fixed_display' : '7.0.4' }
];

vcf::fortios::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
