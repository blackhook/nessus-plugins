#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103934);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-5124",
    "CVE-2017-5125",
    "CVE-2017-5126",
    "CVE-2017-5127",
    "CVE-2017-5128",
    "CVE-2017-5129",
    "CVE-2017-5130",
    "CVE-2017-5131",
    "CVE-2017-5132",
    "CVE-2017-5133",
    "CVE-2017-15386",
    "CVE-2017-15387",
    "CVE-2017-15388",
    "CVE-2017-15389",
    "CVE-2017-15390",
    "CVE-2017-15391",
    "CVE-2017-15392",
    "CVE-2017-15393",
    "CVE-2017-15394",
    "CVE-2017-15395"
  );

  script_name(english:"Google Chrome < 62.0.3202.62 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is
affected by multiple unspecified vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS or Mac OS X
host is prior to 62.0.32. It is, therefore, affected by multiple 
vulnerabilities as noted in Chrome stable channel update release notes
for October 17th 2017. Please refer to the release notes for additional 
information.");
  # https://chromereleases.googleblog.com/2017/10/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?441fea3d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 62.0.3202.62 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5133");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/18");

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

google_chrome_check_version(fix:'62.0.3202.62', severity:SECURITY_WARNING);
