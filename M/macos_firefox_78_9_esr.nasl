## 
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2021-11.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(148013);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/19");

  script_cve_id(
    "CVE-2021-23981",
    "CVE-2021-23982",
    "CVE-2021-23984",
    "CVE-2021-23987",
    "CVE-2021-29955",
    "CVE-2021-29955"
  );
  script_xref(name:"IAVA", value:"2021-A-0144-S");

  script_name(english:"Mozilla Firefox ESR < 78.9");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote macOS or Mac OS X host is prior to 78.9. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2021-11 advisory.

  - A texture upload of a Pixel Buffer Object could have confused the WebGL code to skip binding the buffer
    used to unpack it, resulting in memory corruption and a potentially exploitable information leak or crash.
    (CVE-2021-23981)

  - Using techniques that built on the slipstream research, a malicious webpage could have scanned both an
    internal network's hosts as well as services running on the user's local machine utilizing WebRTC
    connections. (CVE-2021-23982)

  - A malicious extension could have opened a popup window lacking an address bar. The title of the popup
    lacking an address bar should not be fully controllable, but in this situation was. This could have been
    used to spoof a website and attempt to trick the user into providing credentials. (CVE-2021-23984)

  - Mozilla developers and community members Alexis Beingessner, Tyson Smith, Julien Wajsberg, and Matthew
    Gregan reported memory safety bugs present in Firefox 86 and Firefox ESR 78.8. Some of these bugs showed
    evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. (CVE-2021-23987)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-11/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 78.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23987");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

kb_base = 'MacOSX/Firefox';
get_kb_item_or_exit(kb_base+'/Installed');

version = get_kb_item_or_exit(kb_base+'/Version', exit_code:1);
path = get_kb_item_or_exit(kb_base+'/Path', exit_code:1);

is_esr = get_kb_item(kb_base+'/is_esr');
if (isnull(is_esr)) audit(AUDIT_NOT_INST, 'Mozilla Firefox ESR');

mozilla_check_version(version:version, path:path, product:'firefox', esr:TRUE, fix:'78.9', min:'78.0.0', severity:SECURITY_WARNING);
