#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(143045);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id("CVE-2020-6648");
  script_xref(name:"IAVA", value:"2020-A-0440-S");

  script_name(english:"Fortinet FortiOS < 6.2.5 Clear Text Information Disclosure (FG-IR-20-009)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a information disclosure.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote host is running a version of FortiOS prior to 6.2.5. 
It, therefore, is vulnerable to information disclosure from data stored in clear text that can be accessed 
via specific commands run on FortiOS' CLI. An authenticated, remote attacker could obtain sensative information 
up to and including user passwords by running a specific diagnostic command.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-20-009");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version to 6.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6648");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/version", "Host/Fortigate/model");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

app_name = 'FortiOS';
app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

constraints = [
  {'min_version': '0.0', 'fixed_version' : '6.0.12' },
  {'min_version': '6.1', 'fixed_version' : '6.2.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);