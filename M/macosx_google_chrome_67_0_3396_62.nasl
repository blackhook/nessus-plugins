#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110229);
  script_version("1.6");
  script_cvs_date("Date: 2019/04/05 23:25:06");

  script_cve_id(
    "CVE-2018-6123",
    "CVE-2018-6124",
    "CVE-2018-6125",
    "CVE-2018-6126",
    "CVE-2018-6127",
    "CVE-2018-6128",
    "CVE-2018-6129",
    "CVE-2018-6130",
    "CVE-2018-6131",
    "CVE-2018-6132",
    "CVE-2018-6133",
    "CVE-2018-6134",
    "CVE-2018-6135",
    "CVE-2018-6136",
    "CVE-2018-6137",
    "CVE-2018-6138",
    "CVE-2018-6139",
    "CVE-2018-6140",
    "CVE-2018-6141",
    "CVE-2018-6142",
    "CVE-2018-6143",
    "CVE-2018-6144",
    "CVE-2018-6145",
    "CVE-2018-6147"
  );
  script_bugtraq_id(104309);

  script_name(english:"Google Chrome < 67.0.3396.62 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is prior
to 67.0.3396.62. It is, therefore, affected by multiple unspecified
vulnerabilities as noted in Chrome stable channel update release notes
for May 29th, 2018. Please refer to the release notes for additional
information.

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2018/05/stable-channel-update-for-desktop_58.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?e0ac93e8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 67.0.3396.62 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/31");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
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

google_chrome_check_version(fix:'67.0.3396.62', severity:SECURITY_HOLE);
