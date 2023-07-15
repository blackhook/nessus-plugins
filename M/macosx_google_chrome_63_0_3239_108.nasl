#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105357);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-15429");
  script_bugtraq_id(102196);

  script_name(english:"Google Chrome < 63.0.3239.108 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is
affected by multiple unspecified vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS or Mac OS X
host is prior to 63.0.3239.108. It is, therefore, affected by multiple
vulnerabilities as noted in Chrome stable channel update release notes
for Thursday, December 14, 2017. Please refer to the release notes for
additional information.

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2017/12/stable-channel-update-for-desktop_14.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?125c6f30");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 63.0.3239.108 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15429");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'63.0.3239.108', severity:SECURITY_WARNING);
