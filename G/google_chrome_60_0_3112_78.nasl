#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101980);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2017-5091",
    "CVE-2017-5092",
    "CVE-2017-5093",
    "CVE-2017-5094",
    "CVE-2017-5095",
    "CVE-2017-5096",
    "CVE-2017-5097",
    "CVE-2017-5098",
    "CVE-2017-5099",
    "CVE-2017-5100",
    "CVE-2017-5101",
    "CVE-2017-5102",
    "CVE-2017-5103",
    "CVE-2017-5104",
    "CVE-2017-5105",
    "CVE-2017-5106",
    "CVE-2017-5107",
    "CVE-2017-5108",
    "CVE-2017-5109",
    "CVE-2017-5110",
    "CVE-2017-7000"
  );
  script_bugtraq_id(99950);

  script_name(english:"Google Chrome < 60.0.3112.78 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 60.0.3112.78. It is, therefore, affected by the following
vulnerabilities :

  - A use-after-free error exists in IndexedDB due to
    improper handling of cursors during transactions. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2017-5091)

  - A use-after-free error exists in the PPAPI component
    that allows unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2017-5092)

  - An unspecified flaw exists in Blink that is triggered
    when displaying JavaScript alerts in fullscreen mode. An
    unauthenticated, remote attacker can exploit this to
    spoof components in the user interface. (CVE-2017-5093)

  - A type confusion error exists in the 'Extensions
    Bindings' component that is triggered when passing event
    filters. An unauthenticated, remote attacker can exploit
    this to execute arbitrary code. (CVE-2017-5094)

  - An overflow condition exists in PDFium due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2017-5095)

  - An unspecified flaw exists related to 'Android intents'
    that allows an unauthenticated, remote attacker to
    disclose sensitive user information. (CVE-2017-5096)

  - An out-of-bounds read error exists in Skia due to
    improper handling of verb arrays. An unauthenticated,
    remote attacker can exploit this to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2017-5097)

  - A use-after-free error exists in Google V8 that allows
    an unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2017-5098)

  - An out-of-bounds write error exists in the PPAPI
    component that allows an unauthenticated, remote
    attacker to execute arbitrary code. (CVE-2017-5099)

  - A use-after-free error exists in the 'Chrome Apps'
    component that allows an unauthenticated, remote
    attacker to have an unspecified impact. (CVE-2017-5100)

  - Multiple unspecified flaws exist in the OmniBox
    component that allow an unauthenticated, remote attacker
    to spoof URLs in the address bar. (CVE-2017-5101,
    CVE-2017-5105)

  - Multiple uninitialized memory use flaws exist in Skia
    that allow an unauthenticated, remote attacker to have
    an unspecified impact. (CVE-2017-5102, CVE-2017-5103)

  - Multiple unspecified flaws exist that allow an
    unauthenticated, remote attacker to spoof components in
    the user interface. (CVE-2017-5104, CVE-2017-5109)

  - A flaw exists in OmniBox that is triggered as domain
    names containing arbitrary Cyrillic letters are rendered
    in the address bar. An unauthenticated, remote attacker
    can exploit this, via a specially crafted domain name,
    to spoof the URL in the address bar. (CVE-2017-5106)

  - A flaw exists in the SVG filters component due to
    improper handling of floating point multiplication. An
    unauthenticated, remote attacker can exploit this, via a
    timing attack, to extract sensitive user information.
    (CVE-2017-5107)

  - A type confusion error exists in Google V8 that allows
    an unauthenticated, remote attacker to have an
    unspecified impact. (CVE-2017-5108)

  - An unspecified flaw exists in the Payments dialog that
    allows an unauthenticated, remote attacker to spoof
    components in the user interface. (CVE-2017-5110)

  - A type confusion error exists in SQLite due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this to execute arbitrary
    code. (CVE-2017-7000)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2017/07/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36f62a15");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 60.0.3112.78 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7000");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'60.0.3112.78', severity:SECURITY_WARNING);
