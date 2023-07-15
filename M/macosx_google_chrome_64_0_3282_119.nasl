#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106486);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id(
    "CVE-2017-15420",
    "CVE-2018-6031",
    "CVE-2018-6032",
    "CVE-2018-6033",
    "CVE-2018-6034",
    "CVE-2018-6035",
    "CVE-2018-6036",
    "CVE-2018-6037",
    "CVE-2018-6038",
    "CVE-2018-6039",
    "CVE-2018-6040",
    "CVE-2018-6041",
    "CVE-2018-6042",
    "CVE-2018-6043",
    "CVE-2018-6045",
    "CVE-2018-6046",
    "CVE-2018-6047",
    "CVE-2018-6048",
    "CVE-2018-6049",
    "CVE-2018-6050",
    "CVE-2018-6051",
    "CVE-2018-6052",
    "CVE-2018-6053",
    "CVE-2018-6054"
  );
  script_bugtraq_id(102098);

  script_name(english:"Google Chrome < 64.0.3282.119 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
multiple security vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 64.0.3282.119. It is, therefore, affected by multiple
security vulnerabilities as noted in Chrome stable channel update
release notes for January 24th, 2018. Please refer to the
release notes for additional information.

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2018/01/stable-channel-update-for-desktop_24.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?26e44d0b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 64.0.3282.119 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6054");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'64.0.3282.119', severity:SECURITY_WARNING);
