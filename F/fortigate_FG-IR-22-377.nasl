#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165763);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/24");

  script_cve_id("CVE-2022-40684");
  script_xref(name:"IAVA", value:"2022-A-0401-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/11/01");
  script_xref(name:"CEA-ID", value:"CEA-2022-0032");

  script_name(english:"Fortinet Fortigate Authentication Bypass (FG-IR-22-377)");

  script_set_attribute(attribute:"synopsis", value:
"Fortinet Firewall is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of Fortigate installed on the remote host is 7.0.x prior to 7.0.7 or 7.2.x prior to 7.2.2. It is,
therefore, affected by a vulnerability as referenced in the FG-IR-22-377 advisory:

  - An authentication bypass using an alternative path or channel in FortiOS and FortiProxy may allow an unauthenticated
    attacker to perform operations on the administrative interface via specially crafted HTTPS requests.
    (CVE-2022-40684)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.tenable.com/blog/cve-2022-40684-critical-authentication-bypass-in-fortios-and-fortiproxy
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3062e82");
  # https://www.bleepingcomputer.com/news/security/fortinet-warns-admins-to-patch-critical-auth-bypass-bug-immediately/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8df9e8be");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortigate version 7.0.7 / 7.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-40684");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Fortinet FortiOS, FortiProxy, and FortiSwitchManager authentication bypass.');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/version", "Host/Fortigate/model");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

var app_name = 'Fortigate';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name:app_name);

var constraints = [
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.7' },
  { 'min_version' : '7.2.0', 'fixed_version' : '7.2.2' }
];

vcf::fortios::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
