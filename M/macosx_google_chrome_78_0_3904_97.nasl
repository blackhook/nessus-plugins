#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(131021);
  script_version("1.1");
  script_cvs_date("Date: 2019/11/14");

  script_name(english:"Google Chrome < 78.0.3904.97 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 78.0.3904.97. It is, therefore, affected by
a vulnerability as referenced in the 2019_11_stable-channel-update-for-desktop advisory. Note that Nessus has not tested
for this issue but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://chromereleases.googleblog.com/2019/11/stable-channel-update-for-desktop.html");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1021723");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 78.0.3904.97 or later.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'78.0.3904.97', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
