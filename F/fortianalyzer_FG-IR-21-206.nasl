##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163255);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2021-43072");

  script_name(english:"Fortinet FortiAnalyzer Buffer Overflow (FG-IR-21-206)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiAnalyzer that is 5.6.x through 5.6.11, 6.x through 6.0.11, 6.2.x through
6.2.9, 6.4.x through 6.4.7, or 7.x through 7.0.2. It is, therefore, affected by a buffer overflow vulnerability. An
authenticated, remote attacker can exploit this issue, via the TFTP protocol with crafted CLI 'execute restore image'
and 'execute certificate remote' operations, to execute arbitrary code or commands in the system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-21-206");
  script_set_attribute(attribute:"solution", value:
"Update FortiAnalyzer to version 6.4.8, 7.0.3, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43072");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:fortianalyzer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

var app_name = 'FortiAnalyzer';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name:'FortiAnalyzer');

var constraints = [
  { 'min_version': '5.6', 'max_version' : '5.6.11', 'fixed_display' : '6.4.8 / 7.0.3' },
  { 'min_version': '6.0', 'max_version' : '6.0.11', 'fixed_display' : '6.4.8 / 7.0.3' },
  { 'min_version': '6.2', 'max_version' : '6.2.9',  'fixed_display' : '6.4.8 / 7.0.3' },
  { 'min_version': '6.4', 'fixed_version' : '6.4.8' },
  { 'min_version': '7.0', 'fixed_version' : '7.0.3' }
];

vcf::fortios::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
