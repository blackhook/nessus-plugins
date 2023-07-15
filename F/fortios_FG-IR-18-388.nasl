#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(125887);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-13383");
  script_bugtraq_id(108539);
  script_xref(name:"IAVA", value:"0001-A-0004-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/10");

  script_name(english:"Fortinet FortiOS < 5.6.11, 6.0.x < 6.0.5 SSL VPN Heap Buffer Overflow (FG-IR-18-388)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a heap buffer overflow condition.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS prior to 5.6.11 or 6.0.x prior to 6.0.5. It is, therefore, affected by
a heap buffer overflow condition in the SSL VPN web portal due to improper handling of javascript href data. An
unauthenticated, remote attacker can exploit this, by convincing a user to visit a specifically crafted webpage, to
cause a denial of service condition.");
  # https://fortiguard.com/psirt/FG-IR-18-388
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3de925e0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version to 5.6.11, 6.0.5, 6.2.0 or later. Alternatively, apply one of the workarounds
outlined in the linked advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-13383");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('vcf.inc');
include('vcf_extras_fortios.inc');

app_info = vcf::get_app_info(app:'FortiOS', kb_ver:'Host/Fortigate/version');
# This is only for configurations with SSL VPN web portal enabled. 
if (report_paranoia < 2) audit(AUDIT_PARANOID);

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

constraints = [
  { 'fixed_version' : '5.6.0', 'fixed_display' : '5.6.11, 6.0.5, 6.2.0 or later' },
  { 'min_version' : '5.6.0', 'fixed_version' : '5.6.11' },
  { 'min_version' : '6.0.0', 'fixed_version':'6.0.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
