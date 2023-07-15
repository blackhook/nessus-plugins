#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174258);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/19");

  script_cve_id("CVE-2022-43955");

  script_name(english:"Fortinet FortiWeb xss (FG-IR-22-428)");

  script_set_attribute(attribute:"synopsis", value:
"Remote host is affected by a xss vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of FortiWeb installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-22-428 advisory.

  - An improper neutralization of input during web page generation [CWE-79] in the FortiWeb web interface
    7.0.0 through 7.0.3, 6.3.0 through 6.3.21, 6.4 all versions, 6.2 all versions, 6.1 all versions and 6.0
    all versions may allow an unauthenticated and remote attacker to perform a reflected cross site scripting
    attack (XSS) via injecting malicious payload in log entries used to build report. (CVE-2022-43955)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-22-428");
  script_set_attribute(attribute:"solution", value:
"Please upgrade to FortiWeb version 7.2.0 or above 
Please upgrade to FortiWeb version 7.0.4 or above 
Please upgrade to FortiWeb version 6.3.22 or above");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-43955");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:fortiweb");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

var app_name = 'FortiWeb';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');
vcf::fortios::verify_product_and_model(product_name:app_name);

var constraints = [
  { 'min_version' : '6.0.0', 'max_version' : '6.0.8', 'fixed_display' : '6.3.22' },
  { 'min_version' : '6.1.0', 'max_version' : '6.1.3', 'fixed_display' : '6.3.22' },
  { 'min_version' : '6.2.0', 'max_version' : '6.2.7', 'fixed_display' : '6.3.22' },
  { 'min_version' : '6.3.0', 'fixed_version' : '6.3.22' },
  { 'min_version' : '6.4.0', 'max_version' : '6.4.2', 'fixed_display' : '7.0.4' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.4' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
