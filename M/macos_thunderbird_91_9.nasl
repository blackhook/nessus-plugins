## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2022-18.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(160526);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/03");

  script_cve_id(
    "CVE-2022-1520",
    "CVE-2022-29909",
    "CVE-2022-29911",
    "CVE-2022-29912",
    "CVE-2022-29913",
    "CVE-2022-29914",
    "CVE-2022-29916",
    "CVE-2022-29917"
  );
  script_xref(name:"IAVA", value:"2022-A-0190-S");

  script_name(english:"Mozilla Thunderbird < 91.9");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote macOS or Mac OS X host is prior to 91.9. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2022-18 advisory.

  - When viewing an email message A, which contains an attached message B, where B is encrypted or digitally
    signed or both, Thunderbird may show an incorrect encryption or signature status. After opening and
    viewing the attached message B, when returning to the display of message A, the message A might be shown
    with the security status of message B. (CVE-2022-1520)

  - When reusing existing popups Thunderbird would allow them to cover the fullscreen notification UI, which
    could enable browser spoofing attacks. (CVE-2022-29914)

  - Documents in deeply-nested cross-origin browsing contexts could obtain permissions granted to the top-
    level origin, bypassing the existing prompt and wrongfully inheriting the top-level permissions.
    (CVE-2022-29909)

  - Thunderbird would behave slightly differently for already known resources, when loading CSS resources
    through resolving CSS variables. This could be used to probe the browser history. (CVE-2022-29916)

  - Thunderbird did not properly protect against top-level navigations for iframe sandbox with a policy
    relaxed through a keyword like <code>allow-top-navigation-by-user-activation</code>. (CVE-2022-29911)

  - Requests initiated through reader mode did not properly omit cookies with a SameSite attribute.
    (CVE-2022-29912)

  - The parent process would not properly check whether the Speech Synthesis feature is enabled, when
    receiving instructions from a child process. (CVE-2022-29913)

  - Mozilla developers Gabriele Svelto, Tom Ritter and the Mozilla Fuzzing Team reported memory safety bugs
    present in Thunderbird 91.8. Some of these bugs showed evidence of memory corruption and we presume that
    with enough effort some of these could have been exploited to run arbitrary code. (CVE-2022-29917)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-18/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 91.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29917");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

mozilla_check_version(version:version, path:path, product:'thunderbird', esr:FALSE, fix:'91.9', severity:SECURITY_HOLE);
