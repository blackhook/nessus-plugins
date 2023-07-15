#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2018-26.
# The text itself is copyright (C) Mozilla Foundation.

include("compat.inc");

if (description)
{
  script_id(118397);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id(
    "CVE-2018-12388",
    "CVE-2018-12390",
    "CVE-2018-12391",
    "CVE-2018-12392",
    "CVE-2018-12393",
    "CVE-2018-12395",
    "CVE-2018-12396",
    "CVE-2018-12397",
    "CVE-2018-12398",
    "CVE-2018-12399",
    "CVE-2018-12400",
    "CVE-2018-12401",
    "CVE-2018-12402",
    "CVE-2018-12403"
  );

  script_name(english:"Mozilla Firefox < 63 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox installed on the remote Windows host is
prior to 63. It is, therefore, affected by multiple vulnerabilities :

  - During HTTP Live Stream playback on Firefox for Android, audio
    data can be accessed across origins in violation of security
    policies. Because the problem is in the underlying Android
    service, this issue is addressed by treating all HLS streams as
    cross-origin and opaque to access. *Note: this issue only affects
    Firefox for Android. Desktop versions of Firefox are unaffected.*
    (CVE-2018-12391)

  - When manipulating user events in nested loops while opening a
    document through script, it is possible to trigger a potentially
    exploitable crash due to poor event handling. (CVE-2018-12392)

  - A potential vulnerability was found in 32-bit builds where an
    integer overflow during the conversion of scripts to an internal
    UTF-16 representation could result in allocating a buffer too
    small for the conversion. This leads to a possible out-of-bounds
    write. *Note: 64-bit builds are not vulnerable to this issue.*
    (CVE-2018-12393)

  - By rewriting the Host request headers using the webRequest API, a
    WebExtension can bypass domain restrictions through domain
    fronting. This would allow access to domains that share a host
    that are otherwise restricted. (CVE-2018-12395)

  - A vulnerability where a WebExtension can run content scripts in
    disallowed contexts following navigation or other events. This
    allows for potential privilege escalation by the WebExtension on
    sites where content scripts should not be run. (CVE-2018-12396)

  - A WebExtension can request access to local files without the
    warning prompt stating that the extension will 'Access your data
    for all websites' being displayed to the user. This allows
    extensions to run content scripts in local pages without
    permission warnings when a local file is opened. (CVE-2018-12397)

  - By using the reflected URL in some special resource URIs, such as
    chrome:, it is possible to inject stylesheets and bypass Content
    Security Policy (CSP). (CVE-2018-12398)

  - When a new protocol handler is registered, the API accepts a title
    argument which can be used to mislead users about which domain is
    registering the new protocol. This may result in the user
    approving a protocol handler that they otherwise would not have.
    (CVE-2018-12399)

  - In private browsing mode on Firefox for Android, favicons are
    cached in the cache/icons folder as they are in non-private mode.
    This allows information leakage of sites visited during private
    browsing sessions. *Note: this issue only affects Firefox for
    Android. Desktop versions of Firefox are unaffected.*
    (CVE-2018-12400)

  - Some special resource URIs will cause a non-exploitable crash if
    loaded with optional parameters following a '?' in the parsed
    string. This could lead to denial of service (DOS) attacks.
    (CVE-2018-12401)

  - SameSite cookies are sent on cross-origin requests when the 'Save
    Page As...' menu item is selected to save a page, violating cookie
    policy. This can result in saving the wrong version of resources
    based on those cookies. (CVE-2018-12402)

  - If a site is loaded over a HTTPS connection but loads a favicon
    resource over HTTP, the mixed content warning is not displayed to
    users. (CVE-2018-12403)

  - Mozilla developers and community members Christian Holler, Dana
    Keeler, Ronald Crane, Marcia Knous, Tyson Smith, Daniel Veditz,
    and Steve Fink reported memory safety bugs present in Firefox 62.
    Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort that some of these could be
    exploited to run arbitrary code. (CVE-2018-12388)

  - Mozilla developers and community members Christian Holler, Bob
    Owen, Boris Zbarsky, Calixte Denizet, Jason Kratzer, Jed Davis,
    Taegeon Lee, Philipp, Ronald Crane, Raul Gurzau, Gary Kwong, Tyson
    Smith, Raymond Forbes, and Bogdan Tara reported memory safety bugs
    present in Firefox 62 and Firefox ESR 60.2. Some of these bugs
    showed evidence of memory corruption and we presume that with
    enough effort that some of these could be exploited to run
    arbitrary code. (CVE-2018-12390)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1301547
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc2c2cb7");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1379411
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c645d5e");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1422456
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?62d886c6");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1442010
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?614520ad");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1443748
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99f950cc");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1448305
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9811edbe");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1460538
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6969f4f");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1467523
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4146eabd");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1469486
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec6f6183");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1469916
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8089c07f");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1471427
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd1081d2");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1472639
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf41751c");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1478843
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a30fef4e");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1481844
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75a288c2");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1482122
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca6d9c31");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1483602
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5c1931e");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1483699
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56a8a5aa");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1483905
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10a58f5f");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1484753
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce604af2");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1484905
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56bedc2c");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1485698
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0940e1a6");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1486314
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?16df5cdc");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1487098
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fa35353");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1487167
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?984d8e82");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1487478
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ce74e28");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1487660
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6af37c5b");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1488061
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5a6c0ca4");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1488803
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?55d351a5");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1490234
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82482803");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1490276
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e7bb037e");
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
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1498482
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3a7cc16");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1498701
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef389f56");
  # https://www.mozilla.org/en-US/security/advisories/mfsa2018-26/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6eea10ba");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 63 or later.");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'63.0.0', severity:SECURITY_HOLE);
