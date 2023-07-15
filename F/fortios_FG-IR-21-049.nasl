#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156752);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/19");

  script_cve_id("CVE-2021-26109");
  script_xref(name:"IAVA", value:"2021-A-0574-S");

  script_name(english:"Fortinet FortiOS Integer Overflow (FG-IR-21-049)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a integer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS prior or equal to 6.0.12, 6.2.x prior or equal to 6.2.9, 6.4.x prior 
or equal to 6.4.5 or 7.0.0. It is, therefore, affected by an integer overflow vulnerability in FortiOS SSLVPN memory 
allocator may allow an unauthenticated attacker to corrupt control data on the heap via specifically crafted requests 
to SSLVPN, resulting in potentially arbitrary code execution.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-21-049");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26109");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/version", "Host/Fortigate/model");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

var app_name = 'FortiOS';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');
var model = get_kb_item_or_exit('Host/Fortigate/model');

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

# For new high-end F-Series Models (FG-180xF, FG-260xF, FG-350xF, FG-420xF, FG-440xF) please upgrade to 6.2.9.
# For FG-6000F, FG7000E and FG7000F Series Models please upgrade to 6.2.9
var constraints = '';

if ((model =~ "(18|26|35|42|44)[0-9]{2}F") || (model =~ "6[0-9]{3}F") || (model =~ "7[0-9]{3}[EF]"))
  constraints = [{ 'fixed_version' : '6.2.9' },];

else
  constraints = [
    { 'min_version': '0.0', 'fixed_version' : '6.0.13' },
    { 'min_version': '6.2', 'fixed_version' : '6.2.10' },
    { 'min_version': '6.4', 'fixed_version' : '6.4.6' },
    { 'min_version': '7.0', 'fixed_version' : '7.0.1' }
  ];

vcf::fortios::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
