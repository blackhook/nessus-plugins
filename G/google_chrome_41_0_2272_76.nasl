#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81647);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2015-1213",
    "CVE-2015-1214",
    "CVE-2015-1215",
    "CVE-2015-1216",
    "CVE-2015-1217",
    "CVE-2015-1218",
    "CVE-2015-1219",
    "CVE-2015-1220",
    "CVE-2015-1221",
    "CVE-2015-1222",
    "CVE-2015-1223",
    "CVE-2015-1224",
    "CVE-2015-1225",
    "CVE-2015-1226",
    "CVE-2015-1227",
    "CVE-2015-1228",
    "CVE-2015-1229",
    "CVE-2015-1230",
    "CVE-2015-1231",
    "CVE-2015-1232",
    "CVE-2015-2239"
  );
  script_bugtraq_id(
    72901,
    72912,
    72916,
    73349,
    74855
  );

  script_name(english:"Google Chrome < 41.0.2272.76 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 41.0.2272.76. It is, therefore, affected by the following
vulnerabilities :

  - Multiple out-of-bounds write errors exist in skia
    filters and media. (CVE-2015-1212, CVE-2015-1213,
    CVE-2015-1214, CVE-2015-1215)

  - Multiple use-after-free errors exist in v8 bindings,
    DOM, GIF decoder, web databases, and service workers,
    which allow arbitrary code execution. (CVE-2015-1216,
    CVE-2015-1218, CVE-2015-1220, CVE-2015-1221,
    CVE-2015-1222, CVE-2015-1223)

  - Multiple type confusion errors exist in v8 bindings that
    allow arbitrary code execution. (CVE-2015-1217,
    CVE-2015-1230)

  - An integer overflow error exists in the WebGL that
    allows arbitrary code execution. (CVE-2015-1219)

  - Multiple out-of-bounds read errors exist in vpxdecoder
    and pdfium that allow unauthorized access to
    information. (CVE-2015-1224, CVE-2015-1225)

  - A validation error exists in the debugger.
    (CVE-2015-1226)

  - Multiple uninitialized value errors exist in blink and
    rendering. (CVE-2015-1227, CVE-2015-1228)

  - A cookie-injection vulnerability exists due to a failure
    to properly handle a 407 HTTP status code accompanied by
    a Set-Cookie header. (CVE-2015-1229)

  - Multiple, unspecified errors exist that allow remote
    attackers to cause a denial of service condition.
    (CVE-2015-1231)

  - An out-of-bounds write flaw exists due to an array index
    error in the DispatchSendMidiData() function that occurs
    when handling a port index supplied by a renderer. A
    remote attacker can exploit this to cause a denial of
    service condition. (CVE-2015-1232)

  - A spoofing vulnerability exists due to improper
    interaction between the '1993 search' features and
    restore-from-disk RELOAD transitions when Instant
    Extended mode is used. A remote attacker can exploit
    this to spoof the address bar for a search-results page.
    (CVE-2015-2239");
  # http://googlechromereleases.blogspot.com/2015/03/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dbe2503e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 41.0.2272.76 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1232");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/05");

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

google_chrome_check_version(installs:installs, fix:'41.0.2272.76', severity:SECURITY_HOLE);
