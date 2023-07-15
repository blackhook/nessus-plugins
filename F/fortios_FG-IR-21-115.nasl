#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156550);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/17");

  script_cve_id("CVE-2021-36173");
  script_xref(name:"IAVA", value:"2021-A-0574-S");

  script_name(english:"Fortinet FortiOS Heap-based Buffer Overflow (FG-IR-21-115)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a heap-based buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS prior to 6.0.13, 6.2.x prior or equal to 6.2.9, 6.4.x prior or equal 
to 6.4.6, 7.0.x prior or equal to 7.0.1, FortiOS-6K7 prior to 6.0.10, 6.2.x prior or equal to 6.2.7, 6.4.x prior or 
equal to 6.4.2. It is, therefore, affected by a heap-based buffer overflow vulnerability in the firmware signature 
verification function of FortiOS may allow an attacker to execute arbitrary code via specially crafted installation 
images.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-21-115");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36173");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/version", "Host/Fortigate/model");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

var app_name = 'Fortigate';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name:app_name);

var model = get_kb_item_or_exit('Host/Fortigate/model');

# Upgrade to FortiOS-6K7K version 6.4.3 and above.
# Upgrade to FortiOS-6K7K version 6.2.8 and above.
var constraints = '';

# FortiOS-6K7K model sample
# https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/8f15cc78-0762-11ec-8f3f-00505692583a/fortigate-6000-7000-v6.0.13-release-notes.pdf
# https://docs.fortinet.com/document/fortigate-6000/6.2.4/fortigate-6000-handbook/769261/whats-new-for-fortigate-6000-6-2-4
if (model =~ "[6-7][0-9]{3}\w")
  constraints = [
    { 'min_version': '0.0', 'max_version' : '6.0.10','fixed_version' : '6.2.8' },
    { 'min_version': '6.2', 'fixed_version' : '6.2.8' },
    { 'min_version': '6.4', 'fixed_version' : '6.4.3' },
  ];

# FortiGate E-series and F-series models released in 2019 and later (specifically: 
# 40F, 60F, 200F, 400E, 600E, 1100E, 1800F, 2200E, 2600F, 3300E, 3400E, 3500F, 3600E and 7121F)

else if (model =~ "-([46]0F|200F|[46]00E|(11|22|33|34|36)00E|(18|26|35)00F|7121F)")
  constraints = [
    { 'min_version': '0.0', 'fixed_version' : '6.0.14' },
    { 'min_version': '6.2', 'fixed_version' : '6.2.10' },
    { 'min_version': '6.4', 'fixed_version' : '6.4.7' },
    { 'min_version': '7.0', 'fixed_version' : '7.0.2' }
  ];

else
  audit(AUDIT_HOST_NOT, 'an affected model');

vcf::fortios::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);