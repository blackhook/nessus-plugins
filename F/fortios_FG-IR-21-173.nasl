#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156569);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/19");

  script_cve_id("CVE-2021-42757");
  script_xref(name:"IAVA", value:"2021-A-0574-S");

  script_name(english:"Fortinet FortiOS Buffer Overflow (FG-IR-21-173)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS prior to 6.0.13, 6.2.x prior or equal to 6.2.9, 6.4.x prior or equal 
to 6.4.7, 7.0.x prior or equal to 7.0.2 or FortiOS-6K7K version prior to 6.2.8. It is, therefore, affected by a buffer 
overflow vulnerability in the TFTP client library of FortiOS, may allow an authenticated local attacker to achieve 
arbitrary code execution via specially crafted command line arguments.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-21-173");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42757");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/version");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

var app_name = 'FortiOS';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');
var model = get_kb_item_or_exit('Host/Fortigate/model');

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

# Upgrade to FortiOS-6K7K 6.2.9 or above.
# https://www.fortinet.com/content/dam/fortinet/assets/data-sheets/FortiGate_6000F_Series.pdf
var constraints = '';

if (model =~ "-[6-7][0-9]{3}[A-Z]")
  constraints = [
    { 'min_version': '0.0', 'fixed_version' : '6.2.9' }
  ];

else
  constraints = [
    { 'min_version': '0.0', 'fixed_version' : '6.0.14' },
    { 'min_version': '6.2', 'fixed_version' : '6.2.10' },
    { 'min_version': '6.4', 'fixed_version' : '6.4.8' },
    { 'min_version': '7.0', 'fixed_version' : '7.0.3' },
  ];

vcf::fortios::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
