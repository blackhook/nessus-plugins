#%NASL_MIN_LEVEL 70300
## 
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2022-10.
# The text itself is copyright (C) Mozilla Foundation.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158693);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/03");

  script_cve_id(
    "CVE-2022-0843",
    "CVE-2022-26381",
    "CVE-2022-26382",
    "CVE-2022-26383",
    "CVE-2022-26384",
    "CVE-2022-26385",
    "CVE-2022-26387"
  );
  script_xref(name:"IAVA", value:"2022-A-0103-S");

  script_name(english:"Mozilla Firefox < 98.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote macOS or Mac OS X host is prior to 98.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2022-10 advisory.

  - When resizing a popup after requesting fullscreen access, the popup would not display the fullscreen
    notification. (CVE-2022-26383)

  - If an attacker could control the contents of an iframe sandboxed with <code>allow-popups</code> but not
    <code>allow-scripts</code>, they were able to craft a link that, when clicked, would lead to JavaScript
    execution in violation of the sandbox. (CVE-2022-26384)

  - When installing an add-on, Firefox verified the signature before prompting the user; but while the user
    was confirming the prompt, the underlying add-on file could have been modified and Firefox would not have
    noticed. (CVE-2022-26387)

  - An attacker could have caused a use-after-free by forcing a text reflow in an SVG object leading to a
    potentially exploitable crash. (CVE-2022-26381)

  - While the text displayed in Autofill tooltips cannot be directly read by JavaScript, the text was rendered
    using page fonts. Side-channel attacks on the text by using specially crafted fonts could have lead to
    this text being inferred by the webpage. (CVE-2022-26382)

  - In unusual circumstances, an individual thread may outlive the thread's manager during shutdown.  This
    could have led to a use-after-free causing a potentially exploitable crash. (CVE-2022-26385)

  - Mozilla developers Kershaw Chang, Ryan VanderMeulen, and Randell Jesup reported memory safety bugs present
    in Firefox 97. Some of these bugs showed evidence of memory corruption and we presume that with enough
    effort some of these could have been exploited to run arbitrary code. (CVE-2022-0843)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-10/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 98.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26384");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include('mozilla_version.inc');

var kb_base = 'MacOSX/Firefox';
get_kb_item_or_exit(kb_base+'/Installed');

var version = get_kb_item_or_exit(kb_base+'/Version', exit_code:1);
var path = get_kb_item_or_exit(kb_base+'/Path', exit_code:1);

var is_esr = get_kb_item(kb_base+'/is_esr');
if (is_esr) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(version:version, path:path, product:'firefox', esr:FALSE, fix:'98.0', severity:SECURITY_HOLE);
