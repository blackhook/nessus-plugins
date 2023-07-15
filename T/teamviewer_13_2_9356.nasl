#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135707);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/23");

  script_cve_id("CVE-2018-16550");

  script_name(english:"TeamViewer Bypass Brute-force Authentication");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that is affected
by an security authentication vulnerability.");
  script_set_attribute(attribute:"description", value:
"TeamViewer versions 10.x through 13.x allows remote attackers to bypass the brute-force authentication 
protection mechanism by skipping the 'Cancel' causing which makes it easier to determine the correct 
value of the default 4-digit PIN.");
  # https://community.teamviewer.com/t5/Announcements/Statement-on-recent-brute-force-research-CVE-2018-16550/m-p/43215
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b46a507");
  script_set_attribute(attribute:"solution", value:
"Upgrade for Teamviewer 10, upgrade to 10.0.134865 or later. For Teamviewer 11, upgrade to 11.0.133222 or later.
For Teamviewer 12, upgrade to 12.0.181268 or later. For Teamviewer 13, upgrade to 13.2.36215. 
For Teamviewer 14, upgrade to 14.2.8352. Alternatively, apply the workarounds outlined in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16550");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:teamviewer:teamviewer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("teamviewer_detect.nasl");
  script_require_keys("SMB/TeamViewer/Installed", "installed_sw/TeamViewer/");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'TeamViewer');

constraints = [
  { 'min_version' : '10.0.0', 'fixed_version' : '10.0.134865' },
  { 'min_version' : '11.0.0', 'fixed_version' : '11.0.133222' },
  { 'min_version' : '12.0.0', 'fixed_version' : '12.0.181268' },
  { 'min_version' : '13.0.0', 'fixed_version' : '13.2.36215' },
  { 'min_version' : '14.0.0', 'fixed_version' : '14.2.8352' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
