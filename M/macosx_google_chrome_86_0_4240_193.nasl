##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142642);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/09");

  script_name(english:"Google Chrome < 86.0.4240.193 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 86.0.4240.193. It is, therefore, affected by
a vulnerability as referenced in the 2020_11_stable-channel-update-for-desktop_9 advisory. Note that Nessus has not
tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2020/11/stable-channel-update-for-desktop_9.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f174f37");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 86.0.4240.193 or later.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'86.0.4240.193', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
