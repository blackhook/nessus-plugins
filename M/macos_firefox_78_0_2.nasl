#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2020-28.
# The text itself is copyright (C) Mozilla Foundation.

include('compat.inc');

if (description)
{
  script_id(138444);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/14");

  script_xref(name:"MFSA", value:"2020-28");

  script_name(english:"Mozilla Firefox < 78.0.2");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote macOS or Mac OS X host is prior to 78.0.2. It is, therefore, affected by
a vulnerability as referenced in the mfsa2020-28 advisory.

  - Using object or embed tags, it was possible to frame
    other websites, even if they disallowed framing using
    the X-Frame-Options header.Note: This issue is
    pending a CVE assignment and will be updated when one is
    available. (MFSA-2020-0003)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-28/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 78.0.2 or later.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include('mozilla_version.inc');

kb_base = 'MacOSX/Firefox';
get_kb_item_or_exit(kb_base+'/Installed');

version = get_kb_item_or_exit(kb_base+'/Version', exit_code:1);
path = get_kb_item_or_exit(kb_base+'/Path', exit_code:1);

is_esr = get_kb_item(kb_base+'/is_esr');
if (is_esr) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(version:version, path:path, product:'firefox', esr:FALSE, fix:'78.0.2', severity:SECURITY_HOLE);
