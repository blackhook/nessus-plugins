#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2020-16.
# The text itself is copyright (C) Mozilla Foundation.

include('compat.inc');

if (description)
{
  script_id(136403);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2020-6831",
    "CVE-2020-12387",
    "CVE-2020-12388",
    "CVE-2020-12389",
    "CVE-2020-12390",
    "CVE-2020-12391",
    "CVE-2020-12392",
    "CVE-2020-12393",
    "CVE-2020-12394",
    "CVE-2020-12395",
    "CVE-2020-12396"
  );
  script_xref(name:"MFSA", value:"2020-16");
  script_xref(name:"IAVA", value:"2020-A-0190-S");

  script_name(english:"Mozilla Firefox < 76.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote macOS or Mac OS X host is prior to 76.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2020-16 advisory.

  - A race condition when running shutdown code for Web
    Worker led to a use-after-free vulnerability. This
    resulted in a potentially exploitable crash.
    (CVE-2020-12387)

  - The Firefox content processes did not sufficiently
    lockdown access control which could result in a sandbox
    escape.Note: this issue only affects Firefox on
    Windows operating systems. (CVE-2020-12388,
    CVE-2020-12389)

  - A buffer overflow could occur when parsing and
    validating SCTP chunks in WebRTC. This could have led to
    memory corruption and a potentially exploitable crash.
    (CVE-2020-6831)

  - Incorrect origin serialization of URLs with IPv6
    addresses could lead to incorrect security checks
    (CVE-2020-12390)

  - Documents formed using data: URLs in an
    object element failed to inherit the CSP of
    the creating context. This allowed the execution of
    scripts that should have been blocked, albeit with a
    unique opaque origin. (CVE-2020-12391)

  - The 'Copy as cURL' feature of Devtools' network tab did
    not properly escape the HTTP POST data of a request,
    which can be controlled by the website. If a user used
    the 'Copy as cURL' feature and pasted the command into a
    terminal, it could have resulted in the disclosure of
    local files. (CVE-2020-12392)

  - The 'Copy as cURL' feature of Devtools' network tab did
    not properly escape the HTTP method of a request, which
    can be controlled by the website. If a user used the
    'Copy as cURL' feature and pasted the command into a
    terminal, it could have resulted in command injection
    and arbitrary command execution.Note: this issue
    only affects Firefox on Windows operating systems.
    (CVE-2020-12393)

  - A logic flaw in our location bar implementation could
    have allowed a local attacker to spoof the current
    location by selecting a different origin and removing
    focus from the input element. (CVE-2020-12394)

  - Mozilla developers and community members Alexandru
    Michis, Jason Kratzer, philipp, Ted Campbell, Bas
    Schouten, Andr Bargull, and Karl Tomlinson reported
    memory safety bugs present in Firefox 75 and Firefox ESR
    68.7. Some of these bugs showed evidence of memory
    corruption and we presume that with enough effort some
    of these could have been exploited to run arbitrary
    code. (CVE-2020-12395)

  - Mozilla developers and community members Frederik Braun,
    Andrew McCreight, C.M.Chang, and Dan Minor reported
    memory safety bugs present in Firefox 75. Some of these
    bugs showed evidence of memory corruption and we presume
    that with enough effort some of these could have been
    exploited to run arbitrary code. (CVE-2020-12396)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-16/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 76.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12395");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-12388");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include('mozilla_version.inc');

kb_base = 'MacOSX/Firefox';
get_kb_item_or_exit(kb_base+'/Installed');

version = get_kb_item_or_exit(kb_base+'/Version', exit_code:1);
path = get_kb_item_or_exit(kb_base+'/Path', exit_code:1);

is_esr = get_kb_item(kb_base+'/is_esr');
if (is_esr) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(version:version, path:path, product:'firefox', esr:FALSE, fix:'76.0', severity:SECURITY_HOLE);

