#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2023-15.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(174165);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2023-0547",
    "CVE-2023-1945",
    "CVE-2023-1999",
    "CVE-2023-29479",
    "CVE-2023-29531",
    "CVE-2023-29532",
    "CVE-2023-29533",
    "CVE-2023-29535",
    "CVE-2023-29536",
    "CVE-2023-29539",
    "CVE-2023-29541",
    "CVE-2023-29542",
    "CVE-2023-29545",
    "CVE-2023-29548",
    "CVE-2023-29550"
  );
  script_xref(name:"IAVA", value:"2023-A-0199-S");

  script_name(english:"Mozilla Thunderbird < 102.10");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote macOS or Mac OS X host is prior to 102.10. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2023-15 advisory.

  - An attacker could have caused an out of bounds memory access using WebGL APIs, leading to memory
    corruption and a potentially exploitable crash. This bug only affects Thunderbird for macOS. Other
    operating systems are unaffected. (CVE-2023-29531)

  - A local attacker can trick the Mozilla Maintenance Service into applying an unsigned update file by
    pointing the service at an update file on a malicious SMB server. The update file can be replaced after
    the signature check, before the use, because the write-lock requested by the service does not work on a
    SMB server. Note: This attack requires local system access and only affects Windows. Other operating
    systems are not affected. (CVE-2023-29532)

  - A website could have obscured the fullscreen notification by using a combination of
    <code>window.open</code>, fullscreen requests, <code>window.name</code> assignments, and
    <code>setInterval</code> calls. This could have led to user confusion and possible spoofing attacks.
    (CVE-2023-29533)

  - Following a Garbage Collector compaction, weak maps may have been accessed before they were correctly
    traced. This resulted in memory corruption and a potentially exploitable crash. (CVE-2023-29535)

  - An attacker could cause the memory manager to incorrectly free a pointer that addresses attacker-
    controlled memory, resulting in an assertion, memory corruption, or a potentially exploitable crash.
    (CVE-2023-29536)

  - OCSP revocation status of recipient certificates was not checked when sending S/Mime encrypted email, and
    revoked certificates would be accepted. Thunderbird versions from 68 to 102.9.1 were affected by this bug.
    (CVE-2023-0547)

  - Certain malformed OpenPGP messages could trigger incorrect parsing of PKESK/SKESK packets due to a bug in
    the Ribose RNP library used by Thunderbird up to version 102.9.1, which would cause the Thunderbird user
    interface to hang. The issue was discovered using Google's oss-fuzz. (CVE-2023-29479)

  - When handling the filename directive in the Content-Disposition header, the filename would be truncated if
    the filename contained a NULL character. This could have led to reflected file download attacks
    potentially tricking users to install malware. (CVE-2023-29539)

  - Thunderbird did not properly handle downloads of files ending in <code>.desktop</code>, which can be
    interpreted to run attacker-controlled commands.  This bug only affects Thunderbird for Linux on certain
    Distributions. Other operating systems are unaffected, and Mozilla is unable to enumerate all affected
    Linux Distributions. (CVE-2023-29541)

  - A newline in a filename could have been used to bypass the file extension security mechanisms that replace
    malicious file extensions such as .lnk  with .download. This could have led to accidental execution of
    malicious code. This bug only affects Thunderbird on Windows. Other versions of Thunderbird are
    unaffected. (CVE-2023-29542)

  - Similar to CVE-2023-28163, this time when choosing 'Save Link As', suggested filenames containing
    environment variable names would have resolved those in the context of the current user.  This bug only
    affects Thunderbird on Windows. Other versions of Thunderbird are unaffected. (CVE-2023-29545)

  - Unexpected data returned from the Safe Browsing API could have led to memory corruption and a potentially
    exploitable crash. (CVE-2023-1945)

  - A wrong lowering instruction in the ARM64 Ion compiler resulted in a wrong optimization result.
    (CVE-2023-29548)

  - Mozilla developers Andrew Osmond, Sebastian Hengst, Andrew McCreight, and the Mozilla Fuzzing Team
    reported memory safety bugs present in Thunderbird 102.9. Some of these bugs showed evidence of memory
    corruption and we presume that with enough effort some of these could have been exploited to run arbitrary
    code. (CVE-2023-29550)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-15/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 102.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29550");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-29542");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_thunderbird_installed.nasl");
  script_require_keys("MacOSX/Thunderbird/Installed");

  exit(0);
}

include('mozilla_version.inc');

var kb_base = 'MacOSX/Thunderbird';
get_kb_item_or_exit(kb_base+'/Installed');

var version = get_kb_item_or_exit(kb_base+'/Version', exit_code:1);
var path = get_kb_item_or_exit(kb_base+'/Path', exit_code:1);

var is_esr = get_kb_item(kb_base+'/is_esr');
if (is_esr) exit(0, 'The Mozilla Thunderbird installation is in the ESR branch.');

mozilla_check_version(version:version, path:path, product:'thunderbird', esr:FALSE, fix:'102.10', severity:SECURITY_HOLE);
