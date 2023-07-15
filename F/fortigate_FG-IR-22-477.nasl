#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172395);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/29");

  script_cve_id("CVE-2022-45861");
  script_xref(name:"IAVA", value:"2023-A-0125-S");

  script_name(english:"Fortinet Fortigate FortiOS 6.2.x < 6.2.14/ 6.4.x < 6.4.12 / 7.0.x < 7.0.10 / 7.2.x < 7.2.4 /  Access of NULL pointer in SSLVPNd (FG-IR-22-477)");

  script_set_attribute(attribute:"synopsis", value:
"Fortinet Firewall is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of Fortigate FortiOS installed on the remote host is 6.2.x < 6.2.14, 6.4.x < 6.4.12,
7.0.x < 7.0.10, or 7.2.x < 7.2.4. It is, therefore, affected by a vulnerability as referenced in
the FG-IR-22-477 advisory:

  - An access of uninitialized pointer vulnerability [CWE-824] in the SSL-VPN portal of FortiOS & FortiProxy
    may allow a remote authenticated attacker to crash the sslvpn daemon via an HTTP GET request.
    (CVE-2022-45861)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-22-477");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortigate FortiOS version 6.2.14 / 6.4.12 / 7.0.10 / 7.2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-45861");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

var app_name = 'Fortigate';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');
vcf::fortios::verify_product_and_model(product_name:app_name);

var constraints = [
  { 'min_version' : '6.2.0', 'fixed_version' : '6.2.14' },
  { 'min_version' : '6.4.0', 'fixed_version' : '6.4.12' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.10' },
  { 'min_version' : '7.2.0', 'fixed_version' : '7.2.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
