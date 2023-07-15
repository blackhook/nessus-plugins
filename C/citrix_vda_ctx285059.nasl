#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150791);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-8269", "CVE-2020-8270", "CVE-2020-8283");
  script_xref(name:"IAVA", value:"2020-A-0523-S");

  script_name(english:"Citrix Virtual Apps and Desktops multiple vulnerabilities (CTX285059)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix Virtual Apps and Desktops installed on the remote Windows host is prior to 7 2006 or prior to
1912 LTSR CU1. It is, therefore, affected by multiple vulnerabilities:

  - An authenticated user on a multi-session VDA can perform arbitrary command execution as SYSTEM. (CVE-2020-8269)

  - An unprivileged Windows user on a VDA with Citrix App-V Service installed OR an SMB user who has connected
    to a VDA with Citrix App-V Service installed can perform arbitrary command execution as SYSTEM. (CVE-2020-8270)

  - An authenticated user on a Windows host that is running Universal Print Server (UPS) can perform arbitrary
    command execution as SYSTEM (CVE-2020-8283)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX285059");
  script_set_attribute(attribute:"solution", value:
"Refer to vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8269");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:virtual_apps_and_desktops");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_virtual_apps_and_desktops_installed.nbin", "citrix_personalization_appv_vda_win_installed.nbin", "citrix_universal_printer_server_win_installed.nbin");
  script_require_keys("installed_sw/Citrix Virtual Apps and Desktops");
  script_require_ports("installed_sw/Citrix Personalization for App-V - VDA", "installed_sw/Citrix Universal Print Server");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Citrix Virtual Apps and Desktops', win_local:TRUE);
var dv = app_info['display_version'];
var cu = app_info['CU'];
var constraints;
var vda = get_kb_item("installed_sw/Citrix Personalization for App-V - VDA");
var ups = get_kb_item("installed_sw/Citrix Universal Print Server");

# checking to see if either Citrix Personalization for App-V - VDA or Citrix Universal Print Server are installed
if (empty_or_null(vda) && empty_or_null(ups)) exit(0, ' Neither Citrix Personalization for App-V - VDA or Citrix Universal Print Server was found to be installed. Host not affected');

if ('LTSR' >< dv)
{
  if (cu >= 2)
    audit(AUDIT_HOST_NOT, "affected");
  else
    constraints = [{ 'min_version' : '7.1912', 'max_version':'7.1912', 'fixed_display' : '7.1912 CU2' }];
}
else
  constraints = [{ 'min_version' : '0.0', 'max_version':'7.2006', 'fixed_display' : '7.2009' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
