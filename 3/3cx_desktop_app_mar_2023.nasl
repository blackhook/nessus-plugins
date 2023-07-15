#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173712);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/19");

  script_cve_id("CVE-2023-29059");
  script_xref(name:"CEA-ID", value:"CEA-2023-0008");

  script_name(english:"3CX DesktopApp Malware");

  script_set_attribute(attribute:"synopsis", value:
"The version of the 3CX DesktopApp installed on the remote host contains malware.");
  script_set_attribute(attribute:"description", value:
"The version of the 3CX DesktopApp installed on the remote host contains malware.

In the absence of a published vendor advisory, current guidance from 3CX and other sources is to uninstall this software
and await an updated version to be published by the vendor.");
  script_set_attribute(attribute:"see_also", value:"https://www.3cx.com/blog/news/desktopapp-security-alert/");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29059");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:3cx:desktop_app");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:3cx:3cx");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("3cx_desktop_app_installed.nbin", "macos_3cx_desktop_app_installed.nbin");
  script_require_keys("installed_sw/3CX Desktop App");

  exit(0);
}

include('vcf.inc');

var app = '3CX Desktop App';
var win_local;
var constraints = make_list();
var fix = 'See vendor blog post';

if (!empty_or_null(get_kb_item('SMB/Registry/Enumerated')))
{
  win_local = TRUE;
  constraints = [
    { 'equal' : '18.12.407', 'fixed_display' : fix },
    { 'equal' : '18.12.416', 'fixed_display' : fix }
  ];
}
else
{
  win_local = FALSE;
  constraints = [
    { 'equal' : '18.11.1213', 'fixed_display' : fix },
    { 'equal' : '18.12.402', 'fixed_display' : fix },
    { 'equal' : '18.12.407', 'fixed_display' : fix },
    { 'equal' : '18.12.416', 'fixed_display' : fix }
  ];
}

var app_info = vcf::get_app_info(app:app, win_local:win_local);
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
