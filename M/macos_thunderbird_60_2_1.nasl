#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2018-25.
# The text itself is copyright (C) Mozilla Foundation.

include("compat.inc");

if (description)
{
  script_id(121478);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/02 21:54:17");

  script_cve_id(
    "CVE-2017-16541",
    "CVE-2018-12376",
    "CVE-2018-12377",
    "CVE-2018-12378",
    "CVE-2018-12379",
    "CVE-2018-12383",
    "CVE-2018-12385",
    "CVE-2018-18499"
  );
  script_xref(name: "MFSA", value: "2018-25");

  script_name(english:"Mozilla Thunderbird < 60.2.1");
  script_summary(english:"Checks the version of Thunderbird.");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote macOS or Mac OS X
host is prior to 60.2.1. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2018-25 advisory.

  - A use-after-free vulnerability can occur when refresh
    driver timers are refreshed in some circumstances during
    shutdown when the timer is deleted while still in use.
    This results in a potentially exploitable crash.
    (CVE-2018-12377)

  - A use-after-free vulnerability can occur when an
    IndexedDB index is deleted while still in use by
    JavaScript code that is providing payload values to be
    stored. This results in a potentially exploitable crash.
    (CVE-2018-12378)

  - A same-origin policy violation allowing the theft of
    cross-origin URL entries when using a <meta>
    meta http-equiv=refresh on a page to cause a
    redirection to another site using
    performance.getEntries(). This is a same-
    origin policy violation and could allow for data theft.
    (CVE-2018-18499)

  - When the Mozilla Updater opens a MAR format file which
    contains a very long item filename, an out-of-bounds
    write can be triggered, leading to a potentially
    exploitable crash. This requires running the Mozilla
    Updater manually on the local system with the malicious
    MAR file in order to occur. (CVE-2018-12379)

  - Browser proxy settings can be bypassed by using the
    automount feature with autofs to create a mount point on
    the local file system. Content can be loaded from this
    mounted file system directly using a file:
    URI, bypassing configured proxy settings. *Note:
    this issue only affects OS X in default configurations.
    On Linux systems, autofs must be installed for the
    vulnerability to occur and Windows is not affected.*
    (CVE-2017-16541)

  - A potentially exploitable crash in
    TransportSecurityInfo used for SSL can be
    triggered by data stored in the local cache in the user
    profile directory. This issue is only exploitable in
    combination with another vulnerability allowing an
    attacker to write data into the local cache or from
    locally installed malware. This issue also triggers a
    non-exploitable startup crash for users switching
    between the Nightly and Release versions of Firefox if
    the same profile is used. (CVE-2018-12385)

  - If a user saved passwords before Firefox 58 and then
    later set a master password, an unencrypted copy of
    these passwords is still accessible. This is because the
    older stored password file was not deleted when the data
    was copied to a new format starting in Firefox 58. The
    new master password is added only on the new file. This
    could allow the exposure of stored password data outside
    of user expectations. (CVE-2018-12383)

  - Mozilla developers and community members Alex Gaynor,
    Boris Zbarsky, Christoph Diehl, Christian Holler, Jason
    Kratzer, Jed Davis, Tyson Smith, Bogdan Tara, Karl
    Tomlinson, Mats Palmgren, Nika Layzell, Ted Campbell,
    and Andrei Cristian Petcu reported memory safety bugs
    present in Firefox 61 and Firefox ESR 60.1. Some of
    these bugs showed evidence of memory corruption and we
    presume that with enough effort that some of these could
    be exploited to run arbitrary code. (CVE-2018-12376)

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-25/");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1470260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1459383");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1468523");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1473113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1412081");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1490585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1475775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1469309");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1469914");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1450989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1480092");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1480517");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1481093");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1478575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1471953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1473161");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1466991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1468738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1483120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1467363");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1472925");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1466577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1467889");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1480521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1478849");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 60.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12377");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/30");

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

include("mozilla_version.inc");

kb_base = "MacOSX/Thunderbird";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

is_esr = get_kb_item(kb_base+"/is_esr");
if (is_esr) exit(0, 'The Mozilla Thunderbird installation is in the ESR branch.');

mozilla_check_version(product:'thunderbird', version:version, path:path, esr:FALSE, fix:'60.2.1', severity:SECURITY_HOLE);
