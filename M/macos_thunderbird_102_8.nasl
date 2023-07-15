#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2023-07.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(171553);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/17");

  script_cve_id(
    "CVE-2023-0616",
    "CVE-2023-0767",
    "CVE-2023-25728",
    "CVE-2023-25729",
    "CVE-2023-25730",
    "CVE-2023-25732",
    "CVE-2023-25734",
    "CVE-2023-25735",
    "CVE-2023-25737",
    "CVE-2023-25738",
    "CVE-2023-25739",
    "CVE-2023-25742",
    "CVE-2023-25746"
  );
  script_xref(name:"IAVA", value:"2023-A-0106-S");

  script_name(english:"Mozilla Thunderbird < 102.8");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote macOS or Mac OS X host is prior to 102.8. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2023-07 advisory.

  - If a MIME email combines OpenPGP and OpenPGP MIME data in a certain way Thunderbird repeatedly attempts to
    process and display the message, which could cause Thunderbird's user interface to lock up and no longer
    respond to the user's actions. An attacker could send a crafted message with this structure to attempt a
    DoS attack. (CVE-2023-0616)

  - The <code>Content-Security-Policy-Report-Only</code> header could allow an attacker to leak a child
    iframe's unredacted URI when interaction with that iframe triggers a redirect. (CVE-2023-25728)

  - A background script invoking <code>requestFullscreen</code> and then blocking the main thread could force
    the browser into fullscreen mode indefinitely, resulting in potential user confusion or spoofing attacks.
    (CVE-2023-25730)

  - An attacker could construct a PKCS 12 cert bundle in such a way that could allow for arbitrary memory
    writes via PKCS 12 Safe Bag attributes being mishandled. (CVE-2023-0767)

  - Cross-compartment wrappers wrapping a scripted proxy could have caused objects from other compartments to
    be stored in the main compartment resulting in a use-after-free after unwrapping the proxy.
    (CVE-2023-25735)

  - An invalid downcast from <code>nsTextNode</code> to <code>SVGElement</code> could have lead to undefined
    behavior. (CVE-2023-25737)

  - Members of the <code>DEVMODEW</code> struct set by the printer device driver weren't being validated and
    could have resulted in invalid values which in turn would cause the browser to attempt out of bounds
    access to related variables. This bug only affects Thunderbird on Windows. Other operating systems are
    unaffected. (CVE-2023-25738)

  - Module load requests that failed were not being checked as to whether or not they were cancelled causing a
    use-after-free in <code>ScriptLoadContext</code>. (CVE-2023-25739)

  - Permission prompts for opening external schemes were only shown for <code>ContentPrincipals</code>
    resulting in extensions being able to open them without user interaction via
    <code>ExpandedPrincipals</code>. This could lead to further malicious actions such as downloading files or
    interacting with software already installed on the system. (CVE-2023-25729)

  - When encoding data from an <code>inputStream</code> in <code>xpcom</code> the size of the input being
    encoded was not correctly calculated potentially leading to an out of bounds memory write.
    (CVE-2023-25732)

  - After downloading a Windows <code>.url</code> shortcut from the local filesystem, an attacker could supply
    a remote path that would lead to unexpected network requests from the operating system.  This also had the
    potential to leak NTLM credentials to the resource. This bug only affects Thunderbird on Windows. Other
    operating systems are unaffected. (CVE-2023-25734)

  - When importing a SPKI RSA public key as ECDSA P-256, the key would be handled incorrectly causing the tab
    to crash. (CVE-2023-25742)

  - Mozilla developers Philipp and Gabriele Svelto reported memory safety bugs present in Thunderbird 102.7.
    Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of
    these could have been exploited to run arbitrary code. (CVE-2023-25746)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-07/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 102.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25746");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/16");

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

mozilla_check_version(version:version, path:path, product:'thunderbird', esr:FALSE, fix:'102.8', severity:SECURITY_HOLE);
