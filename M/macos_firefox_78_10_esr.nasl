## 
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2021-15.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(148774);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/19");

  script_cve_id(
    "CVE-2021-23961",
    "CVE-2021-23994",
    "CVE-2021-23995",
    "CVE-2021-23998",
    "CVE-2021-23999",
    "CVE-2021-24002",
    "CVE-2021-29945",
    "CVE-2021-29946"
  );
  script_xref(name:"IAVA", value:"2021-A-0185-S");

  script_name(english:"Mozilla Firefox ESR < 78.10");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote macOS or Mac OS X host is prior to 78.10. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2021-15 advisory.

  - A WebGL framebuffer was not initialized early enough, resulting in memory corruption and an out of bound
    write. (CVE-2021-23994)

  - When Responsive Design Mode was enabled, it used references to objects that were previously freed. We
    presume that with enough effort this could have been exploited to run arbitrary code. (CVE-2021-23995)

  - Through complicated navigations with new windows, an HTTP page could have inherited a secure lock icon
    from an HTTPS page. (CVE-2021-23998)

  - Further techniques that built on the slipstream research combined with a malicious webpage could have
    exposed both an internal network's hosts as well as services running on the user's local machine.
    (CVE-2021-23961)

  - If a Blob URL was loaded through some unusual user interaction, it could have been loaded by the System
    Principal and granted additional privileges that should not be granted to web content. (CVE-2021-23999)

  - When a user clicked on an FTP URL containing encoded newline characters (%0A and %0D), the newlines would
    have been interpreted as such and allowed arbitrary commands to be sent to the FTP server.
    (CVE-2021-24002)

  - The WebAssembly JIT could miscalculate the size of a return type, which could lead to a null read and
    result in a crash. Note: This issue only affected x86-32 platforms. Other platforms are unaffected.
    (CVE-2021-29945)

  - Ports that were written as an integer overflow above the bounds of a 16-bit integer could have bypassed
    port blocking restrictions when used in the Alt-Svc header. (CVE-2021-29946)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-15/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 78.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29946");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

mozilla_check_version(version:version, path:path, product:'firefox', esr:TRUE, fix:'78.10', min:'78.0.0', severity:SECURITY_WARNING);
