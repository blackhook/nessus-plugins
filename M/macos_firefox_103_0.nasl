## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2022-28.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(163496);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/06");

  script_cve_id(
    "CVE-2022-2505",
    "CVE-2022-36314",
    "CVE-2022-36315",
    "CVE-2022-36316",
    "CVE-2022-36317",
    "CVE-2022-36318",
    "CVE-2022-36319",
    "CVE-2022-36320"
  );
  script_xref(name:"IAVA", value:"2022-A-0298-S");

  script_name(english:"Mozilla Firefox < 103.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote macOS or Mac OS X host is prior to 103.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2022-28 advisory.

  - When combining CSS properties for overflow and transform, the mouse cursor could interact with different
    coordinates than displayed. (CVE-2022-36319)

  - When visiting a website with an overly long URL, the user interface would start to hang. Due to session
    restore, this could lead to a permanent Denial of Service. This bug only affects Firefox for Android.
    Other operating systems are unaffected. (CVE-2022-36317)

  - When visiting directory listings for `chrome://` URLs as source text, some parameters were reflected.
    (CVE-2022-36318)

  - When opening a Windows shortcut from the local filesystem, an attacker could supply a remote path that
    would lead to unexpected network requests from the operating system. This bug only affects Firefox for
    Windows. Other operating systems are unaffected. (CVE-2022-36314)

  - When loading a script with Subresource Integrity, attackers with an injection capability could trigger the
    reuse of previously cached entries with incorrect, different integrity metadata. (CVE-2022-36315)

  - When using the Performance API, an attacker was able to notice subtle differences between
    PerformanceEntries and thus learn whether the target URL had been subject to a redirect. (CVE-2022-36316)

  - Mozilla developers and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 102. Some
    of these bugs showed evidence of memory corruption and we presume that with enough effort some of these
    could have been exploited to run arbitrary code. (CVE-2022-2505, CVE-2022-36320)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-28/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 103.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-36320");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include('mozilla_version.inc');

var kb_base = 'MacOSX/Firefox';
get_kb_item_or_exit(kb_base+'/Installed');

var version = get_kb_item_or_exit(kb_base+'/Version', exit_code:1);
var path = get_kb_item_or_exit(kb_base+'/Path', exit_code:1);

var is_esr = get_kb_item(kb_base+'/is_esr');
if (is_esr) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(version:version, path:path, product:'firefox', esr:FALSE, fix:'103.0', severity:SECURITY_HOLE);
