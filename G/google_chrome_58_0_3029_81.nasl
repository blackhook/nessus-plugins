#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99633);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2017-5057",
    "CVE-2017-5058",
    "CVE-2017-5059",
    "CVE-2017-5060",
    "CVE-2017-5061",
    "CVE-2017-5062",
    "CVE-2017-5063",
    "CVE-2017-5064",
    "CVE-2017-5065",
    "CVE-2017-5066",
    "CVE-2017-5067",
    "CVE-2017-5069"
  );
  script_bugtraq_id(97939);

  script_name(english:"Google Chrome < 58.0.3029.81 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 58.0.3029.81. It is, therefore, affected by the following
vulnerabilities :

  - A type confusion error exists in PDFium in the
    CJS_Object::GetEmbedObject() function that allows an
    unauthenticated, remote attacker to have an unspecified
    impact. (CVE-2017-5057)

  - A use-after-free error exists in Print Preview that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2017-5058)

  - A type confusion error exists in Blink due to improper
    handling of pseudo-elements in layout trees. An
    unauthenticated, remote attacker can exploit this to
    have an unspecified impact. (CVE-2017-5059)

  - A spoofing vulnerability exists in url_formatter.cc due
    to improper handling of Cyrillic letters in domain
    names. An unauthenticated, remote attacker can exploit
    this to spoof URLs in the address bar. (CVE-2017-5060)

  - A flaw exists in the Omnibox component that is triggered
    as unloaded content may be rendered in a compositor
    frame after a navigation commit. An unauthenticated,
    remote attacker can exploit this to spoof URLs in the
    address bar. (CVE-2017-5061)

  - A use-after-free error exists in the Apps component that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2017-5062)

  - A heap-based buffer overflow condition exists in the
    Skia component in the spanSlowRate() function in
    SkLinearBitmapPipeline_sample.h due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this to cause a denial of
    service condition or the execution arbitrary code.
    (CVE-2017-5063)

  - A use-after-free error exists in Blink that allows an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2017-5064)

  - A flaw exists in Blink due to a failure to properly
    close validation bubbles when uploading a document. An
    unauthenticated, remote attacker can exploit this to
    cause an unspecified impact. (CVE-2017-5065)

  - A flaw exists in the Networking component due to a
    failure to verify certificate chains that have
    mismatching signature algorithms. An unauthenticated,
    remote attacker can exploit this to have an unspecified
    impact. (CVE-2017-5066)

  - An unspecified flaw exists in the Omnibox component that
    allows an unauthenticated, remote attacker to spoof
    URLs. (CVE-2017-5067)

  - A same-origin policy bypass vulnerability exists in the
    PingLoader::sendViolationReport() function in
    PingLoader.cpp due to improper handling of HTTP
    Content-Type headers in CSP or XSS auditor violation
    reports. An unauthenticated, remote attacker can exploit
    this to bypass the same-origin policy. (CVE-2017-5069)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2017/04/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9ef6b47");
  script_set_attribute(attribute:"see_also", value:"https://www.xudongz.com/blog/2017/idn-phishing/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 58.0.3029.81 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5064");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/24");

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

google_chrome_check_version(installs:installs, fix:'58.0.3029.81', severity:SECURITY_WARNING);

