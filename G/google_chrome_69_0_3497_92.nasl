#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117429);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-17458", "CVE-2018-17459");

  script_name(english:"Google Chrome < 69.0.3497.92 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by a
vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is prior to 69.0.3497.92. It is, therefore, affected by 
multiple vulnerabilities as referenced in the Google Chrome stable channel update release notes for
2018/09/11.

- An improper update of the WebAssembly dispatch table in WebAssembly in Google Chrome prior to 69.0.3497.92 allowed a 
remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page (CVE-2018-17458).

- Incorrect handling of clicks in the omnibox in Navigation in Google Chrome prior to 69.0.3497.92 allowed a remote 
attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page (CVE-2018-17459).

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's 
self-reported version number.");
  # https://chromereleases.googleblog.com/2018/09/stable-channel-update-for-desktop_11.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?138bca57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 69.0.3497.92 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-17458");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'69.0.3497.92', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);
