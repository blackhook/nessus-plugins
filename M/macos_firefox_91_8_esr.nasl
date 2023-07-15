#%NASL_MIN_LEVEL 70300
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2022-14.
# The text itself is copyright (C) Mozilla Foundation.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159528);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/03");

  script_cve_id(
    "CVE-2022-1097",
    "CVE-2022-1196",
    "CVE-2022-24713",
    "CVE-2022-28281",
    "CVE-2022-28282",
    "CVE-2022-28285",
    "CVE-2022-28286",
    "CVE-2022-28289"
  );
  script_xref(name:"IAVA", value:"2022-A-0134-S");

  script_name(english:"Mozilla Firefox ESR < 91.8");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote macOS or Mac OS X host is prior to 91.8. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2022-14 advisory.

  - <code>NSSToken</code> objects were referenced via direct points, and could have been accessed in an unsafe
    way on different threads, leading to a use-after-free and potentially exploitable crash. (CVE-2022-1097)

  - If a compromised content process sent an unexpected number of WebAuthN Extensions in a Register command to
    the parent process, an out of bounds write would have occurred leading to memory corruption and a
    potentially exploitable crash. (CVE-2022-28281)

  - After a VR Process is destroyed, a reference to it may have been retained and used, leading to a use-
    after-free and potentially exploitable crash. (CVE-2022-1196)

  - By using a link with <code>rel=localization</code> a use-after-free could have been triggered by
    destroying an object during JavaScript execution and then referencing the object through a freed pointer,
    leading to a potential exploitable crash. (CVE-2022-28282)

  - When generating the assembly code for <code>MLoadTypedArrayElementHole</code>, an incorrect AliasSet was
    used. In conjunction with another vulnerability this could have been used for an out of bounds memory
    read. (CVE-2022-28285)

  - Due to a layout change, iframe contents could have been rendered outside of its border. This could have
    led to user confusion or spoofing attacks. (CVE-2022-28286)

  - The rust regex crate did not properly prevent crafted regular expressions from taking an arbitrary amount
    of time during parsing. If an attacker was able to supply input to this crate, they could have caused a
    denial of service in the browser. (CVE-2022-24713)

  - Mozilla developers and community members Nika Layzell, Andrew McCreight, Gabriele Svelto, and the Mozilla
    Fuzzing Team reported memory safety bugs present in Firefox 98 and Firefox ESR 91.7. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. (CVE-2022-28289)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-14/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 91.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24713");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-28289");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

var kb_base = 'MacOSX/Firefox';
get_kb_item_or_exit(kb_base+'/Installed');

var version = get_kb_item_or_exit(kb_base+'/Version', exit_code:1);
var path = get_kb_item_or_exit(kb_base+'/Path', exit_code:1);

var is_esr = get_kb_item(kb_base+'/is_esr');
if (isnull(is_esr)) audit(AUDIT_NOT_INST, 'Mozilla Firefox ESR');

mozilla_check_version(version:version, path:path, product:'firefox', esr:TRUE, fix:'91.8', min:'91.0.0', severity:SECURITY_WARNING);
