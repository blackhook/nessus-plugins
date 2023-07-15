#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104886);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id("CVE-2017-14186");
  script_bugtraq_id(101955);

  script_name(english:"Fortinet FortiOS <= 5.4 / 5.6.x < 5.6.8 / 6.0.x < 6.0.5 SSL VPN Web Portal login redir XSS (FG-IR-17-242)");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Fortinet FortiOS running on the remote host is prior or equal to 5.4, 5.6.x prior to 5.6.8, or 6.0.x
prior to 6.0.5. It is, therefore, affected by a cross-site scripting (XSS) vulnerability in the SSL VPN web portal due
to a failure to sanitize the login redir parameter. An unauthenticated, remote attacker can exploit this, by convincing
a user to click on a specially crafted URL, to execute arbitrary script code in a user's browser session or to redirect 
the user to a malicious website.");
  # https://fortiguard.com/psirt/FG-IR-17-242
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3c15f32");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version 5.6.8 / 6.0.5 / 6.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14186");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version", "Settings/ParanoidReport");

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
  { 'max_version' : '5.4', 'fixed_display' : '5.6.8 / 6.0.5 / 6.2.0 or later' },
  { 'min_version' : '5.6.0', 'fixed_version' : '5.6.8' },
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE, flags:{xss:true});
