#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131320);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id("CVE-2019-6697", "CVE-2019-15705");
  script_xref(name:"IAVA", value:"2019-A-0432-S");
  script_xref(name:"IAVA", value:"2019-A-0439-S");

  script_name(english:"Fortinet FortiOS < 6.0.7 / 6.2.x < 6.2.2 Multiple Vulnerabilities (FG-IR-19-184, FG-IR-19-236)");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS prior to 6.0.7 or 6.2.x prior to 6.2.2.

It is, therefore, affected by multiple vulnerabilities :

  - A Cross-site Scripting (XSS) vulnerability in the FortiGate DHCP
    monitor page alllows an unauthenticated attacker in the same
    network as the FortiGate to perform a Stored Cross Site
    Scripting attack. (CVE-2019-6697)

  - A Denial of Service vulnerability exists in the SSL VPN portal of
    FortiOS that allows an unauthenticated remote attacker to crash
    the SSL VPN service by sending a crafted POST request.
    (CVE-2019-15705)");
  # https://fortiguard.com/psirt/FG-IR-19-184
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d597af8");
  # https://fortiguard.com/psirt/FG-IR-19-236
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bde71b65");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version to 6.0.7, 6.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6697");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/26");

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

include('audit.inc');
include('vcf.inc');
include('vcf_extras_fortios.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = 'FortiOS';

app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

constraints = [
  { 'min_version':'0.0.0', 'max_version':'6.0.6', 'fixed_version':'6.0.7'},
  { 'min_version':'6.2.0', 'max_version':'6.2.1', 'fixed_version':'6.2.2'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:true});
