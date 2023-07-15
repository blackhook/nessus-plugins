#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158687);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/19");

  script_cve_id("CVE-2021-41017");
  script_xref(name:"IAVA", value:"2021-A-0574-S");

  script_name(english:"Fortinet FortiWeb < 6.3.16 / 6.4.x < 6.4.2 Heap-Based Buffer Overflow (FG-IR-21-160)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by heap-base buffer overflow vulnerability");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiWeb prior or equal to 6.3.15 or 6.4.x prior or equal to 6.4.1. It is, 
therefore, affected by a multiple heap-based buffer overflow vulnerability in web API controllers of FortiWeb. 
An authenticated, remote attacker can exploit this issue, by sending a specially crafted HTTP requests to execute 
arbitrary code or commands in the system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-21-160");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41017");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:fortiweb");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}


include('vcf.inc');
include('vcf_extras_fortios.inc');

var app_name = 'FortiWeb';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');
var model = get_kb_item_or_exit('Host/Fortigate/model');

# Make sure device is FortiWeb.
vcf::fortios::verify_product_and_model(product_name:'FortiWeb');

#FortiWeb 6.4.1 and below.  Upgrade to FortiWeb version 6.4.2 or above.
#FortiWeb 6.3.15 and below. Upgrade to FortiWeb version 6.3.16 or above.
var constraints = [
    { 'min_version': '0.0', 'fixed_version' : '6.3.16' },
    { 'min_version': '6.4', 'fixed_version' : '6.4.2' },
  ];

vcf::fortios::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
