#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134228);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id("CVE-2019-6696");
  script_xref(name:"IAVA", value:"2020-A-0038-S");

  script_name(english:"Fortinet FortiOS 5.x >= 5.4.0 / 6.x < 6.0.9 / 6.2.x < 6.2.2 URL Redirection Vulnerability (FG-IR-19-179)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a URL redirection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS 5.x greater than or
equal to 5.4.0, 6.x prior to 6.0.9, or 6.2.x prior to 6.2.2. It is,
therefore, affected by a URL redirection vulnerability due to an
input-validation flaw related to the admin password change page.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-19-179");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version to 6.0.9, 6.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6696");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('vcf.inc');
include('vcf_extras_fortios.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = 'FortiOS';

app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

constraints = [
  {'min_version':'5.4.0', 'fixed_version':'6.0.9'},
  {'min_version':'6.2.0', 'fixed_version':'6.2.2'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
