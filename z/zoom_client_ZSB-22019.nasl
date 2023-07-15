#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(168799);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/16");

  script_cve_id("CVE-2022-28757");

  script_name(english:"Zoom Client for Meetings 5.7.3 < 5.11.6 Vulnerability (ZSB-22019)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Zoom Client for Meetings installed on the remote host is between 5.7.3 and 5.11.6. It is, therefore,
affected by a vulnerability as referenced in the ZSB-22019 advisory.

  - The Zoom Client for Meetings for macOS (Standard and for IT Admin) starting with version 5.7.3  and before
    5.11.6 contains a vulnerability in the auto update process. A local low-privileged user could exploit this
    vulnerability to escalate their privileges to root. Note: This issue allows for a bypass of the patch
    issued in 5.11.5 to address CVE-2022-28756. Users can help keep themselves secure by applying current
    updates or downloading the latest Zoom software with all current security updates from
    https://zoom.us/download. (CVE-2022-28757)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://explore.zoom.us/en/trust/security/security-bulletin/?filter-cve=&filter=&keywords=ZSB-22019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1d3e277");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zoom Client for Meetings 5.11.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28757");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:zoom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:meetings");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_zoom_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "installed_sw/zoom");

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
  { 'min_version' : '5.7.3', 'fixed_version' : '5.11.6' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
