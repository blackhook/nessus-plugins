#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165765);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_cve_id("CVE-2022-29059");

  script_name(english:"FortiWeb: FortiWeb - SQLi in delete filter component (FG-IR-22-140)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of FortiWeb installed on the remote host is affected by a vulnerability as referenced in the FG-IR-22-140
advisory:

  - An improper neutralization of special elements used in an SQL command('SQL Injection') vulnerability
    [CWE-89] in FortiWeb may allow a privileged attacker to execute SQL commands over the log database via
    specifically crafted strings parameters. (CVE-2022-29059)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.fortinet.com/psirt/FG-IR-22-140");
  script_set_attribute(attribute:"solution", value:
"Upgrade to FortiWeb version 7.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29059");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:fortiweb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

var app_name = 'FortiWeb';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');
vcf::fortios::verify_product_and_model(product_name:app_name);

var constraints = [
  { 'min_version' : '6.2.3', 'max_version' : '6.2.7',  'fixed_display' : '7.0.2' },
  { 'min_version' : '6.3.0', 'max_version' : '6.3.18', 'fixed_display' : '7.0.2' },
  { 'min_version' : '6.4.0', 'max_version' : '6.4.2',  'fixed_display' : '7.0.2' },
  { 'min_version' : '7.0.0', 'max_version' : '7.0.1',  'fixed_display' : '7.0.2' },
];

vcf::fortios::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'sqli':TRUE}
);
