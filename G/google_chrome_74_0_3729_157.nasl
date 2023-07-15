#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125371);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Google Chrome < 74.0.3729.157 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by a
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 74.0.3729.157. It is, therefore, affected by a vulnerability
as referenced in the 2019_05_stable-channel-update-for-desktop
advisory. Note that Nessus has not tested for this issue but has
instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2019/05/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7121bfc6");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/963080");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 74.0.3729.157 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on in depth analysis of the vendor advisory by Tenable.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}
include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'74.0.3729.157', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
