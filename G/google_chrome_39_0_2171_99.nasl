#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(80485);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2015-0301",
    "CVE-2015-0302",
    "CVE-2015-0303",
    "CVE-2015-0304",
    "CVE-2015-0305",
    "CVE-2015-0306",
    "CVE-2015-0307",
    "CVE-2015-0308",
    "CVE-2015-0309"
  );
  script_bugtraq_id(
    72031,
    72032,
    72033,
    72034,
    72035,
    72036,
    72037,
    72038,
    72039
  );

  script_name(english:"Google Chrome < 39.0.2171.99 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is a
version prior to 39.0.2171.99. It is, therefore, affected by the
following vulnerabilities :

  - An unspecified improper file validation issue.
    (CVE-2015-0301)

  - An unspecified information disclosure vulnerability,
    which can be exploited to capture keystrokes.
    (CVE-2015-0302)

  - Multiple memory corruption vulnerabilities allow an
    attacker to execute arbitrary code. (CVE-2015-0303,
    CVE-2015-0306)

  - Multiple heap-based buffer overflow vulnerabilities
    that can be exploited to execute arbitrary code.
    (CVE-2015-0304, CVE-2015-0309)

  - An unspecified type confusion vulnerability that can
    lead to code execution. (CVE-2015-0305)

  - An out-of-bounds read vulnerability that can be
    exploited to leak memory addresses. (CVE-2015-0307)

  - A use-after-free vulnerability that results in arbitrary
    code execution. (CVE-2015-0308)");
  # http://googlechromereleases.blogspot.com/2015/01/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d2c2d8b");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-01.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 39.0.2171.99 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0309");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'39.0.2171.99', severity:SECURITY_HOLE, xss:FALSE);
