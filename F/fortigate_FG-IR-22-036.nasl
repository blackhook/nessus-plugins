##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163711);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id("CVE-2022-23442");

  script_name(english:"Fortinet Fortigate -- Inter-VDOM information leaking (FG-IR-22-036)");

  script_set_attribute(attribute:"synopsis", value:
"Fortinet Firewall is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of Fortigate installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-22-036 advisory.

  - An improper access control vulnerability [CWE-284] in FortiOSmay allow an authenticated attacker with a
    restricted user profile to gather the checksum information about the other VDOMsvia CLI commands.
    (CVE-2022-23442)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortigate version 6.4.9 / 7.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23442");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/version", "Host/Fortigate/model", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

get_kb_item_or_exit('Host/Fortigate/model');
var app_info = vcf::get_app_info(app:'FortiOS', kb_ver:'Host/Fortigate/version');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

vcf::fortios::verify_product_and_model(product_name:'FortiGate');


var constraints = [
  { 'min_version' : '6.2.0', 'fixed_version' : '6.4.9' },
  { 'min_version' : '7.0.0', 'max_version' : '7.0.5', 'fixed_version' : '7.0.6' }
];

vcf::fortios::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
