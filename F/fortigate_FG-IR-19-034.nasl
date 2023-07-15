#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129782);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id("CVE-2019-5586", "CVE-2019-5588");
  script_xref(name:"IAVA", value:"0001-A-0006-S");

  script_name(english:"Fortinet FortiGate 5.2.0 < 5.6.11 / 6.0.x < 6.0.5 XSS (FG-IR-19-034)");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a FortiOS version prior to 6.2.1. It is, therefore, affected by a cross-site scripting
vulnerability. An unauthenticated attacker on the same subnet may be able perform a reflected cross-site scripting
attack by injecting unsantized input into multiple parameters of the error page HTTP request.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-19-034");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version 6.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5586");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

app_name = 'FortiOS';
app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

constraints = [
  {'min_version':'5.2.0', 'fixed_version':'5.6.11'},
  {'min_version':'6.0.0', 'fixed_version':'6.0.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{'xss':TRUE});
