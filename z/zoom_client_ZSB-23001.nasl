#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(174469);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id("CVE-2023-22880");

  script_name(english:"Zoom Client for Meetings < 5.13.3 Vulnerability / Zoom VDI < 5.13.1 Information Disclosure (ZSB-23001)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by an Information Disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Zoom Client for Meetings installed on the remote host is prior to 5.13.3., or the version of Zoom VDI 
isntalled on the remote host is prior to 5.13.1. It is, therefore, affected by a the Information Disclosure vulnerability
as referenced in the ZSB-23001 advisory.

  - Zoom for Windows clients before version 5.13.3, Zoom Rooms for Windows clients before version 5.13.5 and Zoom VDI 
    for Windows clients before 5.13.1 contain an information disclosure vulnerability. A recent update to the Microsoft 
    Edge WebView2 runtime used by the affected Zoom clients, transmitted text to Microsoft’s online Spellcheck service 
    instead of the local Windows Spellcheck. Updating Zoom remediates this vulnerability by disabling the feature. 
    Updating Microsoft Edge WebView2 Runtime to at least version 109.0.1481.0 and restarting Zoom remediates this 
    vulnerability by updating Microsoft’s telemetry behavior. Users can help keep themselves secure by applying current 
    updates or downloading the latest Zoom software with all current security updates from https://zoom.us/download. 
    (CVE-2022-28764)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://explore.zoom.us/en/trust/security/security-bulletin/?filter-cve=&filter=&keywords=ZSB-23001
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b6ba427");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zoom Client for Meetings 5.13.3 / Zoom VDI 5.13.1 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22880");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:zoom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:meetings");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zoom_client_for_meetings_win_installed.nbin");
  script_require_ports("installed_sw/Zoom Client for Meetings", "installed_sw/Zoom Client for VDI", "installed_sw/zoom");

  exit(0);
}

include('vcf.inc');

var app_info = NULL;

if (get_kb_item('installed_sw/Zoom Client for Meetings'))
  app_info = vcf::get_app_info(app:'Zoom Client for Meetings', win_local:TRUE);
else if (get_kb_item('installed_sw/Zoom Client for VDI'))
  app_info = vcf::get_app_info(app:'Zoom Client for VDI', win_local:TRUE);  
else
  app_info = vcf::get_app_info(app:'zoom');

vcf::check_granularity(app_info:app_info, sig_segments:3);

vcf::check_all_backporting(app_info:app_info);

var constraints;
if (app_info['app'] == "Zoom Client for Meetings")
{
  constraints = [{ 'fixed_version' : '5.13.3' }];
}
if (app_info['app'] == "Zoom Client for VDI")
{
  constraints = [{ 'fixed_version' : '5.13.1' }];
}
else
{
  constraints = [{ 'fixed_version' : '5.13.3' }];
}

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
