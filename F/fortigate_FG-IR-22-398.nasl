#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168637);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/24");

  script_cve_id("CVE-2022-42475");
  script_xref(name:"IAVA", value:"2022-A-0512-S");
  script_xref(name:"CEA-ID", value:"CEA-2022-0038");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/01/03");

  script_name(english:"Fortinet Fortigate heap-based buffer overflow in sslvpnd (FG-IR-22-398)");

  script_set_attribute(attribute:"synopsis", value:
"Fortinet Firewall is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of Fortigate installed on the remote host is 5.0.0 through 5.0.14, 5.2.0 through 5.2.15, 5.4.0 through
5.4.13, 5.6.0 through 5.6.14, 6.0.0 through 6.0.15, 6.2.x prior to 6.2.12, 6.4.x prior to 6.4.11, 7.0.x prior to 7.0.9,
or 7.2.x prior to 7.2.3. It is, therefore, affected by a heap-based buffer overflow vulnerability as referenced in the
FG-IR-22-398 advisory.

  - A heap-based buffer overflow vulnerability in FortiOS SSL-VPN may allow a remote unauthenticated
    attacker to execute arbitrary code or commands via specifically crafted requests. (CVE-2022-42475)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-22-398");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortigate version 7.2.3, 7.0.9, 6.4.11, or 6.2.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42475");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/12");

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
  { 'min_version' : '5.0.0', 'max_version' : '5.0.14', 'fixed_version' : '6.2.12' },
  { 'min_version' : '5.2.0', 'max_version' : '5.2.15', 'fixed_version' : '6.2.12' },
  { 'min_version' : '5.4.0', 'max_version' : '5.4.13', 'fixed_version' : '6.2.12' },
  { 'min_version' : '5.6.0', 'max_version' : '5.6.14', 'fixed_version' : '6.2.12' },
  { 'min_version' : '6.0.0', 'max_version' : '6.0.15', 'fixed_version' : '6.2.12' },
  { 'min_version' : '6.2.0', 'fixed_version' : '6.2.12' },
  { 'min_version' : '6.4.0', 'fixed_version' : '6.4.11' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.9' },
  { 'min_version' : '7.2.0', 'fixed_version' : '7.2.3' }
];

vcf::fortios::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
