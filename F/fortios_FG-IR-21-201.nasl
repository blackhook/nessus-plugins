##
# (C) Tenable, Inc. 
##

include('compat.inc');

if (description)
{
  script_id(161892);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2021-44168");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/24");

  script_name(english:"Fortinet FortiOS < 6.0.14 / 6.2 < 6.2.10 / 6.4 < 6.4.8 / 7.0 < 7.0.3 Arbitrary File Download (FG-IR-21-201)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an arbitrary file download.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS prior to 6.0.14, 6.2 prior to 6.2.10,
 6.4 prior to 6.4.8, or 7.0 prior to 7.0.3.

It is, therefore, affected by an arbitrary file download vulnerability that could allow 
a local authenticated attacker to download arbitrary files on the device via specially 
crafted update packages.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-21-201");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version to 6.0.14, 6.2.10, 6.4.8, 7.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44168");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin", "ssh_get_info.nasl");
  script_require_keys("Host/Fortigate/version", "Host/Fortigate/model");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

var app_name = 'FortiOS';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

var constraints = [
  {'min_version': '0.0', 'fixed_version': '6.0.14' },
  {'min_version': '6.2', 'fixed_version': '6.2.10' },
  {'min_version': '6.4', 'fixed_version': '6.4.8' },
  {'min_version': '7.0', 'fixed_version': '7.0.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
