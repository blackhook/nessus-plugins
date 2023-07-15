#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94137);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id(
    "CVE-2016-5181",
    "CVE-2016-5182",
    "CVE-2016-5183",
    "CVE-2016-5184",
    "CVE-2016-5185",
    "CVE-2016-5186",
    "CVE-2016-5187",
    "CVE-2016-5188",
    "CVE-2016-5189",
    "CVE-2016-5190",
    "CVE-2016-5191",
    "CVE-2016-5192",
    "CVE-2016-5193",
    "CVE-2016-5194"
  );
  script_bugtraq_id(93528);

  script_name(english:"Google Chrome < 54.0.2840.59 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS or Mac OS X
host is prior to 54.0.2840.59. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple cross-site scripting vulnerabilities exists in
    the Blink and Bookmarks components due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit these, via a specially
    crafted request, to execute arbitrary script code in a
    user's browser session. (CVE-2016-5181, CVE-2016-5191)

  - A heap-based buffer overflow condition exists in Blink
    due to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2016-5182)

  - Multiple use-after-free errors exist in PDFium that
    allow an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2016-5183, CVE-2016-5184)

  - A use-after-free error exists in Blink that allows an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-5185)

  - An out-of-bounds read error exists in the DevTools
    component that allows an unauthenticated, remote
    attacker to disclose memory contents. (CVE-2016-5186)

  - Multiple unspecified flaws exist that allow an
    unauthenticated, remote attacker to spoof URLs.
    (CVE-2016-5187, CVE-2016-5189)

  - An unspecified flaw exists related to the display of
    drop-down menus that allows an unauthenticated, remote
    attacker to disguise user interface elements and conduct
    spoofing attacks. (CVE-2016-5188)

  - A use-after-free error exists in the Internals component
    that allows an unauthenticated, remote attacker to
    execute arbitrary code. (CVE-2016-5190)

  - An unspecified flaw exists in Blink that allows an
    unauthenticated, remote attacker to bypass Cross-Origin
    Resource Sharing (CORS) restrictions. (CVE-2016-5192)

  - An unspecified flaw exists that allows an
    unauthenticated, remote attacker to bypass schemes.
    (CVE-2016-5193)

  - Multiple unspecified flaws exist in the Skia component
    that allow an unauthenticated, remote attacker to impact
    integrity. (CVE-2016-5194)

  - A flaw exists in FrameView.cpp due to improper handling
    of orthogonal writing mode roots with floating siblings.
    An unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2016-5194)

  - A flaw exists in permission_prompt_impl.cc due to
    improper handling of permission bubbles. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted website performing timing attacks, to
    obtain unintended permissions. (CVE-2016-5194)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://googlechromereleases.blogspot.ca/2016/10/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97775924");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 54.0.2840.59 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5194");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'54.0.2840.59', severity:SECURITY_HOLE, xss:TRUE);
