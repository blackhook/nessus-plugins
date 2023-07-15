#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117635);
  script_version("1.1");
  script_cvs_date("Date: 2018/09/21 12:49:03");

  script_name(english:"Google Chrome < 69.0.3497.100 Vulnerability");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by a
vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is
prior to 69.0.3497.100. It is, therefore, affected by a vulnerability
as noted in Google Chrome stable channel update release notes for
2018/09/17. Please refer to the release notes for additional
information. Note that Nessus has not attempted to exploit these
issues but has instead relied only on the application's self-reported
version number.");
  # https://chromereleases.googleblog.com/2018/09/stable-channel-update-for-desktop_17.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3a309c2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 69.0.3497.100 or later.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'69.0.3497.100', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
