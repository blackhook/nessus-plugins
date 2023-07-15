#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177116);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id("CVE-2023-27997");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/07/04");
  script_xref(name:"CEA-ID", value:"CEA-2023-0020");
  script_xref(name:"IAVA", value:"2023-A-0281");

  script_name(english:"Fortinet Fortigate - Heap buffer overflow in sslvpn pre-authentication (FG-IR-23-097)");

  script_set_attribute(attribute:"synopsis", value:
"Fortinet Firewall is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of Fortigate installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-23-097 advisory.

  - A heap-based buffer overflow vulnerability [CWE-122] in FortiOS and FortiProxy SSL-VPN may allow a remote
    attacker to execute arbitrary code or commands via specifically crafted requests. (CVE-2023-27997)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-23-097");
  script_set_attribute(attribute:"solution", value:
"Please upgrade to FortiOS-6K7K version 7.0.12 or above
Please upgrade to FortiOS-6K7K version 6.4.13 or above
Please upgrade to FortiOS-6K7K version 6.2.15 or above
Please upgrade to FortiOS-6K7K version 6.0.17 or above
Please upgrade to FortiProxy version 7.2.4 or above
Please upgrade to FortiProxy version 7.0.10 or above
Please upgrade to FortiOS version 7.4.0 or above
Please upgrade to FortiOS version 7.2.5 or above
Please upgrade to FortiOS version 7.0.12 or above
Please upgrade to FortiOS version 6.4.13 or above
Please upgrade to FortiOS version 6.2.14 or above
Please upgrade to FortiOS version 6.0.17 or above");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-27997");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:fortiproxy");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

# If there's a workaround specified in the advisory we're making this require paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app_name = 'Fortigate';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');
vcf::fortios::verify_product_and_model(product_name:app_name);

var constraints = [
  { 'min_version' : '6.0.0', 'max_version' : '6.0.16', 'fixed_version' : '6.0.17' },
  { 'min_version' : '6.2.0', 'max_version' : '6.2.13', 'fixed_version' : '6.2.14' },
  { 'min_version' : '6.4.0', 'max_version' : '6.4.12', 'fixed_version' : '6.4.13' },
  { 'min_version' : '7.0.0', 'max_version' : '7.0.11', 'fixed_version' : '7.0.12' },
  { 'min_version' : '7.2.0', 'max_version' : '7.2.4', 'fixed_version' : '7.2.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
