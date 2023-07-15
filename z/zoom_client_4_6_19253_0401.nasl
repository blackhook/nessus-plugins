#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135188);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/03");

  script_name(english:"Zoom Client for Meetings < 4.6.19253.0401 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Zoom Client for Meetings installed on the remote Windows host is prior to 4.6.19253.0401. It is,
therefore, affected by the following vulnerabilities:

  - A malicious party can use UNC links to leak a user's hashed password.

  - Users can access chat in a webinar when chat is disabled.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.zoom.us/hc/en-us/articles/201361953-New-Updates-for-Windows
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?774d8ec7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zoom Client for Meetings 4.6.19253.0401 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:zoom:zoom_client_for_meetings");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:zoom_cloud_meetings");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zoom_client_for_meetings_win_installed.nbin");
  script_require_keys("installed_sw/Zoom Client for Meetings", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Zoom Client for Meetings', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '0', 'fixed_version' : '4.6.19253.0401' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
