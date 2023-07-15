#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156754);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/19");

  script_cve_id("CVE-2021-26103");
  script_xref(name:"IAVA", value:"2021-A-0574-S");

  script_name(english:"Fortinet FortiOS CSRF (FG-IR-20-158)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a cross-site request forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS that is 5.6.x, 6.0.x, 6.2.x prior or equal to 6.2.9, 6.4.x prior or 
equal to 6.4.6, 7.0.0. It is, therefore, affected by a cross-site request forgery vulnerability in the user interface 
of FortiGate SSL VPN portal, which may allow a remote, unauthenticated attacker to conduct a cross-site request forgery 
(CSRF) attack . Only SSL VPN in web mode or full mode are impacted by this vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-20-158");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26103");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/version", "Host/Fortigate/model", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

var app_name = 'FortiOS';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');
var model = get_kb_item_or_exit('Host/Fortigate/model');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

constraints = [
  { 'min_version': '5.6', 'fixed_version' : '6.2.10' },
  { 'min_version': '6.4', 'fixed_version' : '6.4.7' },
  { 'min_version': '7.0', 'fixed_version' : '7.0.1' },
];

vcf::fortios::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xsrf':TRUE}
);
