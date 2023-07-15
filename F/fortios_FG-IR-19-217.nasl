#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133358);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id("CVE-2019-17655");
  script_xref(name:"IAVA", value:"2020-A-0038-S");

  script_name(english:"Fortinet FortiOS < 6.2.3 Multiple Vulnerabilities (FG-IR-19-217)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS prior to 6.2.3.
It is, therefore, affected by an information disclosure vulnerability
due to a cleartext storage in a file or on disk. FortiOS SSL VPN
allows an attacker to retrieve a logged-in SSL VPN user's credentials
should that attacker be able to read the session file stored on the
targeted device's system.");
  # https://fortiguard.com/psirt/FG-IR-19-217
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?71396f14");
  # https://blog.orange.tw/2019/08/attacking-ssl-vpn-part-2-breaking-the-fortigate-ssl-vpn.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a42f59f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version to 6.2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17655");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/30");

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
  {'fixed_version':'6.2.3'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
