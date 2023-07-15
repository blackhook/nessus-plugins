##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161660);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id("CVE-2022-22306");
  script_xref(name:"IAVA", value:"2022-A-0221-S");

  script_name(english:"Fortinet FortiOS Certificate Validation (FG-IR-21-239)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a certificate validation vulnerability.");
  script_set_attribute(attribute:"description", value:
"An improper certificate validation vulnerability in FortiOS 6.0.0 through 6.0.14, 6.2.0 through 6.2.10, 6.4.0 through 
6.4.8, 7.0.0 may allow a network adjacent and unauthenticated attacker to man-in-the-middle the communication between 
the FortiGate and some peers such as private SDNs and external cloud platforms.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-21-239");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22306");

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

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/version");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

var app_name = 'FortiOS';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name: app_name);

var constraints = [
    { 'min_version': '6.0', 'max_version' : '6.0.14','fixed_version' : '6.4.9' },
    { 'min_version': '6.2', 'max_version' : '6.2.10','fixed_version' : '6.4.9' },
    { 'min_version': '6.4', 'max_version' : '6.4.8','fixed_version' : '6.4.9' },
    { 'min_version': '7.0', 'fixed_version' : '7.0.1' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
