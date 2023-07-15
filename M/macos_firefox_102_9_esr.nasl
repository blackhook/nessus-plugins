#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2023-10.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(172512);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/13");

  script_cve_id(
    "CVE-2023-25751",
    "CVE-2023-25752",
    "CVE-2023-28162",
    "CVE-2023-28163",
    "CVE-2023-28164",
    "CVE-2023-28176"
  );
  script_xref(name:"IAVA", value:"2023-A-0132-S");

  script_name(english:"Mozilla Firefox ESR < 102.9");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote macOS or Mac OS X host is prior to 102.9. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2023-10 advisory.

  - Sometimes, when invalidating JIT code while following an iterator, the newly generated code could be
    overwritten incorrectly. This could lead to a potentially exploitable crash. (CVE-2023-25751)

  - Dragging a URL from a cross-origin iframe that was removed during the drag could have lead to user
    confusion and website spoofing attacks. (CVE-2023-28164)

  - While implementing on AudioWorklets, some code may have casted one type to another, invalid, dynamic type.
    This could have lead to a potentially exploitable crash. (CVE-2023-28162)

  - When accessing throttled streams, the count of available bytes needed to be checked in the calling
    function to be within bounds. This may have lead future code to be incorrect and vulnerable.
    (CVE-2023-25752)

  - When downloading files through the Save As dialog on Windows with suggested filenames containing
    environment variable names, Windows would have resolved those in the context of the current user.  This
    bug only affects Firefox on Windows. Other versions of Firefox are unaffected. (CVE-2023-28163)

  - Mozilla developers Timothy Nikkel, Andrew McCreight, and the Mozilla Fuzzing Team reported memory safety
    bugs present in Firefox 110 and Firefox ESR 102.8. Some of these bugs showed evidence of memory corruption
    and we presume that with enough effort some of these could have been exploited to run arbitrary code.
    (CVE-2023-28176)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-10/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 102.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28176");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

mozilla_check_version(version:version, path:path, product:'firefox', esr:TRUE, fix:'102.9', min:'102.0.0', severity:SECURITY_HOLE);
