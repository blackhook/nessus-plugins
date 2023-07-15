#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165674);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/02");

  script_cve_id("CVE-2022-28755");

  script_name(english:"Zoom Client < 5.11.0 URL Parsing Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by url parsing vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Zoom Client for Meetings for Android, iOS, Linux, macOS, and Windows before version 5.11.0 is susceptible to a 
URL parsing vulnerability. If a malicious Zoom meeting URL is opened, the malicious link may direct the user to connect 
to an arbitrary network address, leading to additional attacks including the potential for remote code execution 
through launching executables from arbitrary paths.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://explore.zoom.us/en/trust/security/security-bulletin");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zoom Client for Meetings 5.11.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28755");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:zoom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:meetings");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zoom_client_for_meetings_win_installed.nbin", "macosx_zoom_installed.nbin", "zoom_nix_installed.nbin");
  script_require_ports("installed_sw/Zoom Client for Meetings", "installed_sw/zoom");

  exit(0);
}

include('vcf.inc');

var app_info = NULL;

if (get_kb_item('installed_sw/Zoom Client for Meetings'))
  app_info = vcf::get_app_info(app:'Zoom Client for Meetings', win_local:TRUE);
else
  app_info = vcf::get_app_info(app:'zoom');

var constraints = [{ 'fixed_version' : '5.11.0' }];

vcf::check_granularity(app_info:app_info, sig_segments:3);

vcf::check_all_backporting(app_info:app_info);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

