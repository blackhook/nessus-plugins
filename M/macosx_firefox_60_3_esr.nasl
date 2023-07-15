#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2018-27.
# The text itself is copyright (C) Mozilla Foundation.

include("compat.inc");

if (description)
{
  script_id(118394);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id(
    "CVE-2018-12389",
    "CVE-2018-12390",
    "CVE-2018-12391",
    "CVE-2018-12392",
    "CVE-2018-12393",
    "CVE-2018-12395",
    "CVE-2018-12396",
    "CVE-2018-12397"
  );

  script_name(english:"Mozilla Firefox ESR < 60.3 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Firefox ESR.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox ESR installed on the remote macOS host
is prior to 60.3. It is, therefore, affected by multiple
vulnerabilities :

  - During HTTP Live Stream playback on Firefox for Android,
    audio data can be accessed across origins in violation
    of security policies. Because the problem is in the
    underlying Android service, this issue is addressed by
    treating all HLS streams as cross-origin and opaque to
    access. *Note: this issue only affects Firefox for
    Android. Desktop versions of Firefox are unaffected.*
    (CVE-2018-12391)

  - When manipulating user events in nested loops while
    opening a document through script, it is possible to
    trigger a potentially exploitable crash due to poor
    event handling. (CVE-2018-12392)

  - A potential vulnerability was found in 32-bit builds
    where an integer overflow during the conversion of
    scripts to an internal UTF-16 representation could
    result in allocating a buffer too small for the
    conversion. This leads to a possible out-of-bounds
    write. *Note: 64-bit builds are not vulnerable to this
    issue.*
    (CVE-2018-12393)

  - By rewriting the Host request headers using the
    webRequest API, a WebExtension can bypass domain
    restrictions through domain fronting. This would allow
    access to domains that share a host that are
    otherwise restricted. (CVE-2018-12395)

  - A vulnerability where a WebExtension can run content
    scripts in disallowed contexts following navigation or
    other events. This allows for potential privilege
    escalation by the WebExtension on sites where content
    scripts should not be run. (CVE-2018-12396)

  - A WebExtension can request access to local files
    without the warning prompt stating that the extension 
    will 'Access your data for all websites' being displayed
    to the user. This allows extensions to run content
    scripts in local pages without permission warnings when
    a local file is opened. (CVE-2018-12397)

  - Mozilla developers and community members Daniel
    Veditz and Philipp reported memory safety bugs present
    in Firefox ESR 60.2. Some of these bugs showed evidence
    of memory corruption and we presume that with enough
    effort that some of these could be exploited to run
    arbitrary code. (CVE-2018-12389)

  - Mozilla developers and community members Christian
    Holler, Bob Owen, Boris Zbarsky, Calixte Denizet,
    Jason Kratzer, Jed Davis, Taegeon Lee, Philipp, Ronald
    Crane, Raul Gurzau, Gary Kwong, Tyson Smith, Raymond
    Forbes, and Bogdan Tara reported memory safety bugs
    present in Firefox 62 and Firefox ESR 60.2. Some of
    these bugs showed evidence of memory corruption and we
    presume that with enough effort that some of these could
    be exploited to run arbitrary code. (CVE-2018-12390)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1442010
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?614520ad");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1443748
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99f950cc");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1467523
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4146eabd");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1469486
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec6f6183");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1478843
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a30fef4e");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1481844
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75a288c2");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1483602
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5c1931e");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1483699
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56a8a5aa");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1483905
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10a58f5f");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1484905
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56bedc2c");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1487098
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fa35353");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1487478
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ce74e28");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1487660
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6af37c5b");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1488803
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?55d351a5");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1490234
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82482803");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1490561
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6a9565b");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1492524
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5daf782e");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1492823
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?166aa054");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1493347
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a933cb35");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1495011
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39935a02");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1495245
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c5b58d2f");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1496159
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6925998");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1496340
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a31d3226");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1498460
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f93877a1");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1498482
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3a7cc16");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1498701
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef389f56");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1499198
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82d76ead");
  # https://www.mozilla.org/en-US/security/advisories/mfsa2018-27/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7aced437");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 60.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12390");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

is_esr = get_kb_item(kb_base+"/is_esr");
if (isnull(is_esr)) audit(AUDIT_NOT_INST, "Mozilla Firefox ESR");

mozilla_check_version(product:'firefox', version:version, path:path, esr:TRUE, fix:'60.3', min:'60.0', severity:SECURITY_HOLE);
