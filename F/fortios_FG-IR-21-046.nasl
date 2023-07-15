#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152514);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id("CVE-2021-24018");
  script_xref(name:"IAVA", value:"2021-A-0368-S");

  script_name(english:"Fortinet FortiOS <= 6.2.9 / 6.4.x <= 6.4.6 / 7.0.0 Buffer Underwrite (FG-IR-21-046)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a buffer underwrite vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS prior or equal to 6.2.9 or 6.4.x prior or equal to 6.4.6 or 7.0.0. It
is, therefore, affected by a buffer underwriter vulnerability in the firmware verification routine of FortiOS that may
allow an attacker located in the adjacent network to potentially execute arbitrary code via a specifically crafted
firmware image.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-21-046");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version 6.2.10 / 6.4.7 / 7.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-24018");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'min_version': '0.0', 'max_version': '6.2.9', 'fixed_display' : '6.2.10' },
  {'min_version': '6.4.0', 'max_version': '6.4.6', 'fixed_display' : '6.4.7' },
  {'min_version': '7.0', 'fixed_version': '7.0.1' }
];

vcf::fortios::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
