#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(125885);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2018-13379");
  script_bugtraq_id(108693);
  script_xref(name:"IAVA", value:"0001-A-0002-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CISA-NCAS", value:"AA22-011A");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");
  script_xref(name:"CEA-ID", value:"CEA-2021-0020");

  script_name(english:"Fortinet FortiOS 5.4.6 <= 5.4.12 / 5.6.3 < 5.6.8 / 6.0.x < 6.0.5 SSL VPN Directory Traversal (FG-IR-18-384)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS 5.4.6 prior or equal to 5.4.12, 5.6.3 prior to 5.6.8 or 6.0.x prior to
6.0.5. It is, therefore, affected by a directory traversal vulnerability in the SSL VPN web portal, due to an improper
limitation of a pathname to a restricted Directory. An unauthenticated, remote attacker can exploit this, via a
specially crafted HTTP request, to download arbitrary FortiOS system files.");
  # https://fortiguard.com/psirt/FG-IR-18-384
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa8b8063");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version to 5.6.8, 6.0.5, 6.2.0 or later. Alternatively, apply one of the workarounds
outlined in the linked advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-13379");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Fortinet FortiGate SSL VPN File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('vcf.inc');
include('vcf_extras_fortios.inc');

app_info = vcf::get_app_info(app:'FortiOS', kb_ver:'Host/Fortigate/version');
if (report_paranoia < 2) audit(AUDIT_PARANOID);

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

constraints = [
  { 'min_version' : '5.4.6', 'max_version' : '5.4.12', 'fixed_display' : '5.6.8, 6.0.5, 6.2.0 or later' },
  { 'min_version' : '5.6.3', 'fixed_version' : '5.6.8' },
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
