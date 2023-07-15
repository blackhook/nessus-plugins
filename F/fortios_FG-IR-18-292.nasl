##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162313);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/03");

  script_cve_id("CVE-2022-22305");
  script_xref(name:"IAVA", value:"2022-A-0233");

  script_name(english:"Fortinet FortiOS < 6.4 MitM (FG-IR-18-292)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a man in the middle vulnerability.");
  script_set_attribute(attribute:"description", value:
"An improper certificate validation vulnerability in FortiOS allows an adjacent, unauthenticated attacker to
man-in-the-middle communication.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-18-292");
  script_set_attribute(attribute:"solution", value:
"Upgrade to FortiOS version 6.4.0, 7.0.0, or later");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22305");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    { 'fixed_version' : '6.1', 'fixed_display': '6.4.0 / 7.0.0' },
    { 'min_version' : '6.2', 'fixed_version' : '6.3', 'fixed_display': '6.4.0 / 7.0.0' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
