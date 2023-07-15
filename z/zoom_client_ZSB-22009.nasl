#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(168806);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/16");

  script_cve_id("CVE-2022-22787");

  script_name(english:"Zoom Client for Meetings < 5.10.0 Vulnerability (ZSB-22009)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Zoom Client for Meetings installed on the remote host is prior to 5.10.0. It is, therefore, affected by a
vulnerability as referenced in the ZSB-22009 advisory.

  - The Zoom Client for Meetings (for Android, iOS, Linux, macOS, and Windows) before version 5.10.0 fails to
    properly validate the hostname during a server switch request. This issue could be used in a more
    sophisticated attack to trick an unsuspecting user's client to connect to a malicious server when
    attempting to use Zoom services. Users can help keep themselves secure by applying current updates or
    downloading the latest Zoom software with all current security updates from https://zoom.us/download.
    (CVE-2022-22787)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://explore.zoom.us/en/trust/security/security-bulletin/?filter-cve=&filter=&keywords=ZSB-22009
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5f19a6f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zoom Client for Meetings 5.10.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22787");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/15");

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

vcf::check_granularity(app_info:app_info, sig_segments:3);

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'fixed_version' : '5.10.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
