#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171596);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/20");

  script_cve_id("CVE-2023-24486");
  script_xref(name:"IAVA", value:"2023-A-0080");

  script_name(english:"Citrix Workspace App for Linux Privilege Escalation (CTX477618)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix Workspace installed on the remote host is prior to 2302, It is, therefore, affected by a
privilege escalation vulnerability. A local attacker can take over the session of another user using a vulnerable
version of Citrix Workspace App for Linux.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX477618");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix Workspace App for Linux 2302 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24486");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:workspace");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_workspace_app_nix_installed.nbin");
  script_require_keys("installed_sw/Citrix Workspace", "Host/uname");

  exit(0);
}

include('vcf.inc');

var uname = get_kb_item_or_exit('Host/uname');
if ('Linux' >!< uname)
  audit(AUDIT_HOST_NOT, 'a Linux-based operating system');

var app_info = vcf::get_app_info(app:'Citrix Workspace');

# 2302 = 23.02.0.10, can be seen in filename at (at least until the next release):
# https://www.citrix.com/downloads/workspace-app/linux/workspace-app-for-linux-latest.html
var constraints = [
  { 'fixed_version' : '23.02.0.10', 'fixed_display' : '2302 (23.02.0.10)'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
