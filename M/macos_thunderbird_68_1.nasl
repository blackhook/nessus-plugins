#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2019-30.
# The text itself is copyright (C) Mozilla Foundation.


include("compat.inc");

if (description)
{
  script_id(128971);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id(
    "CVE-2019-11739",
    "CVE-2019-11740",
    "CVE-2019-11742",
    "CVE-2019-11743",
    "CVE-2019-11744",
    "CVE-2019-11746",
    "CVE-2019-11752"
  );
  script_xref(name:"MFSA", value:"2019-30");

  script_name(english:"Mozilla Thunderbird < 68.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote macOS or Mac OS X host is prior to 68.1. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2019-30 advisory, including the following:

  - A use-after-free vulnerability can occur while
    manipulating video elements if the body is freed while
    still in use. This results in a potentially exploitable
    crash. (CVE-2019-11746)

  - Some HTML elements, such as <title> and <textarea>, can
    contain literal angle brackets without treating them as
    markup. It is possible to pass a literal closing tag to
    .innerHTML on these elements, and subsequent content
    after that will be parsed as if it were outside the tag.
    This can lead to XSS if a site does not filter user
    input as strictly for these elements as it does for
    other elements. (CVE-2019-11744)

  - It is possible to delete an IndexedDB key value and
    subsequently try to extract it during conversion. This
    results in a use-after-free and a potentially
    exploitable crash. (CVE-2019-11752)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-30/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 68.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11752");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_thunderbird_installed.nasl");
  script_require_keys("MacOSX/Thunderbird/Installed");

  exit(0);
}

include('mozilla_version.inc');

kb_base = 'MacOSX/Thunderbird';
get_kb_item_or_exit(kb_base+'/Installed');

version = get_kb_item_or_exit(kb_base+'/Version', exit_code:1);
path = get_kb_item_or_exit(kb_base+'/Path', exit_code:1);

is_esr = get_kb_item(kb_base+'/is_esr');
if (is_esr) exit(0, 'The Mozilla Thunderbird installation is in the ESR branch.');

mozilla_check_version(version:version, path:path, product:'thunderbird', esr:FALSE, fix:'68.1', severity:SECURITY_HOLE, xss:TRUE);
