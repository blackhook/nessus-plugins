#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2020-20.
# The text itself is copyright (C) Mozilla Foundation.

include('compat.inc');

if (description)
{
  script_id(137048);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/13");

  script_cve_id(
    "CVE-2020-12399",
    "CVE-2020-12405",
    "CVE-2020-12406",
    "CVE-2020-12407",
    "CVE-2020-12408",
    "CVE-2020-12409",
    "CVE-2020-12411"
  );
  script_xref(name:"MFSA", value:"2020-20");
  script_xref(name:"IAVA", value:"2020-A-0238-S");

  script_name(english:"Mozilla Firefox < 77.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote macOS or Mac OS X host is prior to 77.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2020-20 advisory.

  - NSS has shown timing differences when performing DSA
    signatures, which was exploitable and could eventually
    leak private keys. (CVE-2020-12399)

  - When browsing a malicious page, a race condition in our
    SharedWorkerService could occur and lead to a
    potentially exploitable crash. (CVE-2020-12405)

  - Mozilla Developer Iain Ireland discovered a missing type
    check during unboxed objects removal, resulting in a
    crash. We presume that with enough effort that it could
    be exploited to run arbitrary code. (CVE-2020-12406)

  - Mozilla Developer Nicolas Silva found that when using
    WebRender, Firefox would under certain conditions leak
    arbitrary GPU memory to the visible screen. The leaked
    memory content was visible to the user, but not
    observable from web content. (CVE-2020-12407)

  - When browsing a document hosted on an IP address, an
    attacker could insert certain characters to flip domain
    and path information in the address bar.
    (CVE-2020-12408)

  - Mozilla developers Tom Tung and Karl Tomlinson reported
    memory safety bugs present in Firefox 76 and Firefox ESR
    68.8. Some of these bugs showed evidence of memory
    corruption and we presume that with enough effort some
    of these could have been exploited to run arbitrary
    code. (CVE-2020-12409)

  - Mozilla developers :Gijs (he/him), Randell Jesup
    reported memory safety bugs present in Firefox 76. Some
    of these bugs showed evidence of memory corruption and
    we presume that with enough effort some of these could
    have been exploited to run arbitrary code.
    (CVE-2020-12411)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-20/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 77.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12411");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

mozilla_check_version(version:version, path:path, product:'firefox', esr:FALSE, fix:'77.0', severity:SECURITY_HOLE);
