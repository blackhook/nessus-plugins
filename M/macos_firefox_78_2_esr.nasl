#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2020-38.
# The text itself is copyright (C) Mozilla Foundation.

include('compat.inc');

if (description)
{
  script_id(139790);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/14");

  script_cve_id("CVE-2020-15663", "CVE-2020-15664", "CVE-2020-15670");
  script_xref(name:"MFSA", value:"2020-38");
  script_xref(name:"IAVA", value:"2020-A-0391-S");

  script_name(english:"Mozilla Firefox ESR < 78.2");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote macOS or Mac OS X host is prior to 78.2. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2020-38 advisory.

  - If Firefox is installed to a user-writable directory, the Mozilla Maintenance Service would execute
    updater.exe from the install location with system privileges. Although the Mozilla Maintenance Service
    does ensure that updater.exe is signed by Mozilla, the version could have been rolled back to a previous
    version which would have allowed exploitation of an older bug and arbitrary code execution with System
    Privileges.Note: This issue only affected Windows operating systems. Other operating systems are
    unaffected. (CVE-2020-15663)

  - By holding a reference to the eval() function from an about:blank window, a malicious webpage
    could have gained access to the InstallTrigger object which would allow them to prompt the user to install
    an extension. Combined with user confusion, this could result in an unintended or malicious extension
    being installed. (CVE-2020-15664)

  - Mozilla developers Jason Kratzer, Christian Holler, Byron Campen, Tyson Smith reported memory safety bugs
    present in Firefox 79 and Firefox ESR 78.1. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code.
    (CVE-2020-15670)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-38/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 78.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15663");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

mozilla_check_version(version:version, path:path, product:'firefox', esr:TRUE, fix:'78.2', min:'78.0.0', severity:SECURITY_HOLE);


