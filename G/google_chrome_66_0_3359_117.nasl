#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109395);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2018-6084",
    "CVE-2018-6085",
    "CVE-2018-6086",
    "CVE-2018-6087",
    "CVE-2018-6088",
    "CVE-2018-6089",
    "CVE-2018-6090",
    "CVE-2018-6091",
    "CVE-2018-6092",
    "CVE-2018-6093",
    "CVE-2018-6094",
    "CVE-2018-6095",
    "CVE-2018-6096",
    "CVE-2018-6097",
    "CVE-2018-6098",
    "CVE-2018-6099",
    "CVE-2018-6100",
    "CVE-2018-6101",
    "CVE-2018-6102",
    "CVE-2018-6103",
    "CVE-2018-6104",
    "CVE-2018-6105",
    "CVE-2018-6106",
    "CVE-2018-6107",
    "CVE-2018-6108",
    "CVE-2018-6109",
    "CVE-2018-6110",
    "CVE-2018-6111",
    "CVE-2018-6112",
    "CVE-2018-6113",
    "CVE-2018-6114",
    "CVE-2018-6115",
    "CVE-2018-6116",
    "CVE-2018-6117"
  );
  script_bugtraq_id(103917);

  script_name(english:"Google Chrome < 66.0.3359.117 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 66.0.3359.117. It is, therefore, affected by a multiple
unspecified vulnerabilities as noted in Chrome stable channel update
release notes for April 17th, 2018. Please refer to the release notes
for additional information.

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2018/04/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db76b488");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 66.0.3359.117 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6084");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/27");

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

google_chrome_check_version(installs:installs, fix:'66.0.3359.117', severity:SECURITY_HOLE);
