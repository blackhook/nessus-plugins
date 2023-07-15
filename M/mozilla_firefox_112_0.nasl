#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2023-13.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(174076);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/09");

  script_cve_id(
    "CVE-2023-1999",
    "CVE-2023-29531",
    "CVE-2023-29532",
    "CVE-2023-29533",
    "CVE-2023-29534",
    "CVE-2023-29535",
    "CVE-2023-29536",
    "CVE-2023-29537",
    "CVE-2023-29538",
    "CVE-2023-29539",
    "CVE-2023-29540",
    "CVE-2023-29541",
    "CVE-2023-29542",
    "CVE-2023-29543",
    "CVE-2023-29544",
    "CVE-2023-29545",
    "CVE-2023-29546",
    "CVE-2023-29547",
    "CVE-2023-29548",
    "CVE-2023-29549",
    "CVE-2023-29550",
    "CVE-2023-29551"
  );
  script_xref(name:"IAVA", value:"2023-A-0182-S");

  script_name(english:"Mozilla Firefox < 112.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior to 112.0. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2023-13 advisory.

  - An attacker could have caused an out of bounds memory access using WebGL APIs, leading to memory
    corruption and a potentially exploitable crash. This bug only affects Firefox for macOS. Other operating
    systems are unaffected. (CVE-2023-29531)

  - A local attacker can trick the Mozilla Maintenance Service into applying an unsigned update file by
    pointing the service at an update file on a malicious SMB server. The update file can be replaced after
    the signature check, before the use, because the write-lock requested by the service does not work on a
    SMB server. Note: This attack requires local system access and only affects Windows. Other operating
    systems are not affected. (CVE-2023-29532)

  - A website could have obscured the fullscreen notification by using a combination of
    <code>window.open</code>, fullscreen requests, <code>window.name</code> assignments, and
    <code>setInterval</code> calls. This could have led to user confusion and possible spoofing attacks.
    (CVE-2023-29533)

  - Different techniques existed to obscure the fullscreen notification in Firefox and Focus for Android.
    These could have led to potential user confusion and spoofing attacks. This bug only affects Firefox and
    Focus for Android. Other versions of Firefox are unaffected. (CVE-2023-29534)

  - Following a Garbage Collector compaction, weak maps may have been accessed before they were correctly
    traced. This resulted in memory corruption and a potentially exploitable crash. (CVE-2023-29535)

  - An attacker could cause the memory manager to incorrectly free a pointer that addresses attacker-
    controlled memory, resulting in an assertion, memory corruption, or a potentially exploitable crash.
    (CVE-2023-29536)

  - Multiple race conditions in the font initialization could have led to memory corruption and execution of
    attacker-controlled code. (CVE-2023-29537)

  - Under specific circumstances a WebExtension may have received a <code>jar:file:///</code> URI instead of a
    <code>moz-extension:///</code> URI during a load request. This leaked directory paths on the user's
    machine. (CVE-2023-29538)

  - When handling the filename directive in the Content-Disposition header, the filename would be truncated if
    the filename contained a NULL character. This could have led to reflected file download attacks
    potentially tricking users to install malware. (CVE-2023-29539)

  - Using a redirect embedded into <code>sourceMappingUrls</code> could allow for navigation to external
    protocol links in sandboxed iframes without <code>allow-top-navigation-to-custom-protocols</code>.
    (CVE-2023-29540)

  - Firefox did not properly handle downloads of files ending in <code>.desktop</code>, which can be
    interpreted to run attacker-controlled commands.  This bug only affects Firefox for Linux on certain
    Distributions. Other operating systems are unaffected, and Mozilla is unable to enumerate all affected
    Linux Distributions. (CVE-2023-29541)

  - A newline in a filename could have been used to bypass the file extension security mechanisms that replace
    malicious file extensions such as .lnk  with .download. This could have led to accidental execution of
    malicious code. This bug only affects Firefox on Windows. Other versions of Firefox are unaffected.
    (CVE-2023-29542)

  - An attacker could have caused memory corruption and a potentially exploitable use-after-free of a pointer
    in a global object's debugger vector. (CVE-2023-29543)

  - If multiple instances of resource exhaustion occurred at the incorrect time, the garbage collector could
    have caused memory corruption and a potentially exploitable crash. (CVE-2023-29544)

  - Similar to CVE-2023-28163, this time when choosing 'Save Link As', suggested filenames containing
    environment variable names would have resolved those in the context of the current user.  This bug only
    affects Firefox on Windows. Other versions of Firefox are unaffected. (CVE-2023-29545)

  - When recording the screen while in Private Browsing on Firefox for Android the address bar and keyboard
    were not hidden, potentially leaking sensitive information.  This bug only affects Firefox for Android.
    Other operating systems are unaffected. (CVE-2023-29546)

  - When a secure cookie existed in the Firefox cookie jar an insecure cookie for the same domain could have
    been created, when it should have silently failed.  This could have led to a desynchronization in expected
    results when reading from the secure cookie. (CVE-2023-29547)

  - A wrong lowering instruction in the ARM64 Ion compiler resulted in a wrong optimization result.
    (CVE-2023-29548)

  - Under certain circumstances, a call to the <code>bind</code> function may have resulted in the incorrect
    realm.  This may have created a vulnerability relating to JavaScript-implemented sandboxes such as SES.
    (CVE-2023-29549)

  - Mozilla developers Randell Jesup, Andrew Osmond, Sebastian Hengst, Andrew McCreight, and the Mozilla
    Fuzzing Team reported memory safety bugs present in Firefox 111 and Firefox ESR 102.9. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. (CVE-2023-29550)

  - Mozilla developers Randell Jesup, Andrew McCreight, Gabriele Svelto, and the Mozilla Fuzzing Team reported
    memory safety bugs present in Firefox 111. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code.
    (CVE-2023-29551)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-13/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 112.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29551");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

var port = get_kb_item('SMB/transport');
if (!port) port = 445;

var installs = get_kb_list('SMB/Mozilla/Firefox/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Firefox');

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'112.0', severity:SECURITY_HOLE);
