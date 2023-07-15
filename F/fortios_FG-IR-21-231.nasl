##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161606);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id("CVE-2021-43206");
  script_xref(name:"IAVA", value:"2022-A-0221-S");

  script_name(english:"Fortinet FortiOS Sensitive Information Disclosure (FG-IR-21-231)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a sensitive information vulnerability.");
  script_set_attribute(attribute:"description", value:
"A server-generated error message containing sensitive information in Fortinet FortiOS versions prior to 6.0, 6.2 to 
6.2.10, 6.4 to 6.4.9 and 7.0 to 7.0.3 allows malicious webservers to retrieve a web proxy's client username and IP via 
same origin HTTP requests triggering proxy-generated HTTP status codes pages.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-21-231");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43206");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/version");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

var app_name = 'FortiOS';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name: app_name);

var constraints = [
    { 'min_version': '5.6', 'fixed_version' : '6.2.11' },
    { 'min_version': '6.4', 'fixed_version' : '6.4.10' },
    { 'min_version': '7.0', 'fixed_version' : '7.0.4', 'fixed_display' : '7.0.4 / 7.2.0' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);