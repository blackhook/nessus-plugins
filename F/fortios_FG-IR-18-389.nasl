#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(125888);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id("CVE-2018-13382");
  script_bugtraq_id(108697);
  script_xref(name:"IAVA", value:"0001-A-0005-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/10");

  script_name(english:"Fortinet FortiOS 5.4.1 < 5.4.11 / 5.6.x < 5.6.9 / 6.0.x < 6.0.5 SSL VPN Security Bypass (FG-IR-18-389)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS 5.4.1 prior to 5.4.11, 5.6.x prior to 5.6.9 or 6.0.x prior to 6.0.5. It
is, therefore, affected by a security bypass vulnerability in the SSL VPN web portal, due to an error when processing
HTTP requests. A remote, unauthenticated attacker can exploit this, by sending a specially crafted HTTP request to
change the password of an arbitrary SSL VPN web portal user.");
  # https://fortiguard.com/psirt/FG-IR-18-389
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97f9346d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version to 5.4.11, 5.6.9, 6.0.5, 6.2.0 or later. Alternatively, apply one of the
workarounds outlined in the linked advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-13382");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
# there is a workaround
if (report_paranoia < 2) audit(AUDIT_PARANOID);

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

constraints = [
  { 'min_version':'5.4.1', 'fixed_version':'5.4.11'},
  { 'min_version':'5.6.0', 'fixed_version':'5.6.9'},
  { 'min_version':'6.0.0', 'fixed_version':'6.0.5'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
