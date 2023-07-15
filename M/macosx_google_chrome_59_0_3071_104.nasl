#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100992);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-5087", "CVE-2017-5088", "CVE-2017-5089");
  script_bugtraq_id(99096);

  script_name(english:"Google Chrome < 59.0.3071.104 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS or Mac OS X
host is prior to 59.0.3071.104. It is, therefore, affected by the
following vulnerabilities :

  - A security bypass vulnerability exists in the IndexedDB
    component that allows an unauthenticated, remote
    attacker to bypass the sandbox. (CVE-2017-5087)

  - An out-of-bounds read error exists in the V8 component
    that allows an unauthenticated, remote attacker to cause
    a denial of service condition. (CVE-2017-5088)

  - An unspecified flaw exists in the Omnibox address bar
    component that allows an unauthenticated, remote
    attacker to spoof domains. (CVE-2017-5089)

  - Multiple unspecified vulnerabilities exist that allow an
    unauthenticated, remote attacker to have a high severity
    impact.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2017/06/stable-channel-update-for-desktop_15.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?744889a5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 59.0.3071.104 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5088");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/22");

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

google_chrome_check_version(fix:'59.0.3071.104', severity:SECURITY_WARNING);
