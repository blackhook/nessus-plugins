#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102994);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-5111",
    "CVE-2017-5112",
    "CVE-2017-5113",
    "CVE-2017-5114",
    "CVE-2017-5115",
    "CVE-2017-5116",
    "CVE-2017-5117",
    "CVE-2017-5118",
    "CVE-2017-5119",
    "CVE-2017-5120"
  );
  script_bugtraq_id(100610);

  script_name(english:"Google Chrome < 61.0.3163.79 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS or Mac OS X
host is prior to 61.0.3163.79. It is, therefore, affected by the
following vulnerabilities :

  - A use-after-free error exists in PDFium. A unauthenticated, remote
    attacker can exploit this to execute arbitrary code.
    (CVE-2017-5111)

  - A heap buffer overflow condition exists in WebGL that allows an
    unauthenticated, remote attacker to execute arbitrary code.
    (CVE-2017-5112)

  - A heap buffer overflow condition exists in Skia that allows an
    unauthenticated, remote attacker to execute arbitrary code.
    (CVE-2017-5113)

  - An unspecified memory lifecycle issue exists in PDFium that allow
    an unauthenticated, remote attacker to have an unspecified impact
    (CVE-2017-5114)

  - An unspecified type confusion errors exist in V8.
    (CVE-2017-5115, CVE-2017-5116)

  - An unspecified uninitialized value flaws exist in Skia that allows
    an unauthenticated, remote attacker to have an unspecified impact.
    (CVE-2017-5117, CVE-2017-5119)

  - An unspecified security bypass vulnerability exists in Blink. An
    unauthenticated, remote attacker can exploit this to bypass
    content security policy. (CVE-2017-5118)

  - An unspecified flaw allows HTTPS downgrade during redirection.
    (CVE-2017-5120)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2017/09/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67b28931");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 61.0.3163.79 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5116");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/07");

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

google_chrome_check_version(fix:'61.0.3163.79', severity:SECURITY_WARNING);
