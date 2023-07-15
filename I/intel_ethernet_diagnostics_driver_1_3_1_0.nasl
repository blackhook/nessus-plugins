#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171959);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/28");

  script_cve_id("CVE-2015-2291");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/02/10");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/03/03");

  script_name(english:"Intel Ethernet Diagnostics Driver < 1.3.1.0 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Intel Ethernet Diagnostics Driver installed on the remote Windows host is prior to 1.3.1.0. It is,
therefore, affected by an escalation of privilege vulnerability. Using malicious IOCTL calls to the driver, a local
attacker can cause a denial of service or possible execute arbitrary code with kernel privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00051.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c16618d8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Intel Ethernet Diagnostics Driver version 1.3.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2291");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:intel:ethernet_diagnostics_driver_iqvw32.sys");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:intel:ethernet_diagnostics_driver_iqvw64.sys");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("intel_ethernet_diagnostics_driver_win_installed.nbin");
  script_require_keys("installed_sw/Intel Ethernet Diagnostics Driver", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Intel Ethernet Diagnostics Driver');

var constraints = [
  { 'fixed_version' : '1.3.1.0'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
