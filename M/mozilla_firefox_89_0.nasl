#%NASL_MIN_LEVEL 70300
## 
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2021-23.
# The text itself is copyright (C) Mozilla Foundation.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150119);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/10");

  script_cve_id(
    "CVE-2021-29959",
    "CVE-2021-29960",
    "CVE-2021-29961",
    "CVE-2021-29962",
    "CVE-2021-29963",
    "CVE-2021-29964",
    "CVE-2021-29965",
    "CVE-2021-29966",
    "CVE-2021-29967"
  );
  script_xref(name:"IAVA", value:"2021-A-0264-S");

  script_name(english:"Mozilla Firefox < 89.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior to 89.0. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2021-23 advisory.

  - A malicious website that causes an HTTP Authentication dialog to be spawned could trick the built-in
    password manager to suggest passwords for the currently active website instead of the website that
    triggered the dialog. This bug only affects Firefox for Android. Other operating systems are
    unaffected. (CVE-2021-29965)

  - Firefox used to cache the last filename used for printing a file. When generating a filename for printing,
    Firefox usually suggests the web page title. The caching and suggestion techniques combined may have lead
    to the title of a website visited during private browsing mode being stored on disk. (CVE-2021-29960)

  - When styling and rendering an oversized `` element, Firefox did not apply correct clipping which
    allowed an attacker to paint over the user interface. (CVE-2021-29961)

  - Address bar search suggestions in private browsing mode were re-using session data from normal mode.
    This bug only affects Firefox for Android. Other operating systems are unaffected. (CVE-2021-29963)

  - A locally-installed hostile program could send `WMCOPYDATA` messages that Firefox would process
    incorrectly, leading to an out-of-bounds read. This bug only affects Firefox on Windows. Other
    operating systems are unaffected. (CVE-2021-29964)

  - When a user has already allowed a website to access microphone and camera, disabling camera sharing would
    not fully prevent the website from re-enabling it without an additional prompt. This was only possible if
    the website kept recording with the microphone until re-enabling the camera. (CVE-2021-29959)

  - Firefox for Android would become unstable and hard-to-recover when a website opened too many popups.
    This bug only affects Firefox for Android. Other operating systems are unaffected. (CVE-2021-29962)

  - Mozilla developers Christian Holler, Anny Gakhokidze, Alexandru Michis, Gabriele Svelto reported memory
    safety bugs present in Firefox 88 and Firefox ESR 78.11. Some of these bugs showed evidence of memory
    corruption and we presume that with enough effort some of these could have been exploited to run arbitrary
    code. (CVE-2021-29967)

  - Mozilla developers Christian Holler, Tooru Fujisawa, Tyson Smith reported memory safety bugs present in
    Firefox 88. Some of these bugs showed evidence of memory corruption and we presume that with enough effort
    some of these could have been exploited to run arbitrary code. (CVE-2021-29966)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-23/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 89.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29967");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

port = get_kb_item('SMB/transport');
if (!port) port = 445;

installs = get_kb_list('SMB/Mozilla/Firefox/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Firefox');

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'89.0', severity:SECURITY_WARNING);
