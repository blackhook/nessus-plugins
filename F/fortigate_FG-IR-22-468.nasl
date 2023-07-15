#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177264);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/21");

  script_cve_id("CVE-2023-29175");
  script_xref(name:"IAVA", value:"2023-A-0281");

  script_name(english:"Fortinet Fortigate 's map server (FG-IR-22-468)");

  script_set_attribute(attribute:"synopsis", value:
"Fortinet Firewall is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of Fortigate installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-22-468 advisory.

  - An improper certificate validation vulnerability [CWE-295] in FortiOS 6.2 all versions, 6.4 all versions,
    7.0.0 through 7.0.10, 7.2.0 and FortiProxy 1.2 all versions, 2.0 all versions, 7.0.0 through 7.0.9, 7.2.0
    through 7.2.3 may allow a remote and unauthenticated attacker to perform a Man-in-the-Middle attack on the
    communication channel between the vulnerable device and the remote FortiGuard's map server.
    (CVE-2023-29175)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-22-468");
  script_set_attribute(attribute:"solution", value:
"Please upgrade to FortiOS version 7.2.1 or above
Please upgrade to FortiOS version 7.0.11 or above
Please upgrade to FortiProxy version 7.2.4 or above
Please upgrade to FortiProxy version 7.0.10 or above");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29175");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/13");

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

var app_name = 'Fortigate';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');
vcf::fortios::verify_product_and_model(product_name:app_name);

var constraints = [
  { 'min_version' : '6.0.0', 'max_version' : '6.0.16', 'fixed_version' : '7.0.11' },
  { 'min_version' : '6.2.0', 'max_version' : '6.2.14', 'fixed_version' : '7.0.11' },
  { 'min_version' : '6.4.0', 'max_version' : '6.4.12', 'fixed_version' : '7.0.11' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.11' },
  { 'min_version' : '7.2.0', 'max_version' : '7.2.0', 'fixed_version' : '7.2.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
