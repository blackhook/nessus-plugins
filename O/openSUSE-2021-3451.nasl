#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:3451-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154193);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-29980",
    "CVE-2021-29981",
    "CVE-2021-29982",
    "CVE-2021-29983",
    "CVE-2021-29984",
    "CVE-2021-29985",
    "CVE-2021-29986",
    "CVE-2021-29987",
    "CVE-2021-29988",
    "CVE-2021-29989",
    "CVE-2021-29990",
    "CVE-2021-29991",
    "CVE-2021-32810",
    "CVE-2021-38492",
    "CVE-2021-38495",
    "CVE-2021-38496",
    "CVE-2021-38497",
    "CVE-2021-38498",
    "CVE-2021-38500",
    "CVE-2021-38501"
  );
  script_xref(name:"IAVA", value:"2021-A-0366-S");
  script_xref(name:"IAVA", value:"2021-A-0386-S");
  script_xref(name:"IAVA", value:"2021-A-0461-S");
  script_xref(name:"IAVA", value:"2021-A-0405");
  script_xref(name:"IAVA", value:"2021-A-0450-S");

  script_name(english:"openSUSE 15 Security Update : MozillaFirefox (openSUSE-SU-2021:3451-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:3451-1 advisory.

  - Uninitialized memory in a canvas object could have caused an incorrect free() leading to memory corruption
    and a potentially exploitable crash. This vulnerability affects Thunderbird < 78.13, Thunderbird < 91,
    Firefox ESR < 78.13, and Firefox < 91. (CVE-2021-29980)

  - An issue present in lowering/register allocation could have led to obscure but deterministic register
    confusion failures in JITted code that would lead to a potentially exploitable crash. This vulnerability
    affects Firefox < 91 and Thunderbird < 91. (CVE-2021-29981)

  - Due to incorrect JIT optimization, we incorrectly interpreted data from the wrong type of object,
    resulting in the potential leak of a single bit of memory. This vulnerability affects Firefox < 91 and
    Thunderbird < 91. (CVE-2021-29982)

  - Firefox for Android could get stuck in fullscreen mode and not exit it even after normal interactions that
    should cause it to exit. *Note: This issue only affected Firefox for Android. Other operating systems are
    unaffected.*. This vulnerability affects Firefox < 91. (CVE-2021-29983)

  - Instruction reordering resulted in a sequence of instructions that would cause an object to be incorrectly
    considered during garbage collection. This led to memory corruption and a potentially exploitable crash.
    This vulnerability affects Thunderbird < 78.13, Thunderbird < 91, Firefox ESR < 78.13, and Firefox < 91.
    (CVE-2021-29984)

  - A use-after-free vulnerability in media channels could have led to memory corruption and a potentially
    exploitable crash. This vulnerability affects Thunderbird < 78.13, Thunderbird < 91, Firefox ESR < 78.13,
    and Firefox < 91. (CVE-2021-29985)

  - A suspected race condition when calling getaddrinfo led to memory corruption and a potentially exploitable
    crash. *Note: This issue only affected Linux operating systems. Other operating systems are unaffected.*
    This vulnerability affects Thunderbird < 78.13, Thunderbird < 91, Firefox ESR < 78.13, and Firefox < 91.
    (CVE-2021-29986)

  - After requesting multiple permissions, and closing the first permission panel, subsequent permission
    panels will be displayed in a different position but still record a click in the default location, making
    it possible to trick a user into accepting a permission they did not want to. *This bug only affects
    Firefox on Linux. Other operating systems are unaffected.*. This vulnerability affects Firefox < 91 and
    Thunderbird < 91. (CVE-2021-29987)

  - Firefox incorrectly treated an inline list-item element as a block element, resulting in an out of bounds
    read or memory corruption, and a potentially exploitable crash. This vulnerability affects Thunderbird <
    78.13, Thunderbird < 91, Firefox ESR < 78.13, and Firefox < 91. (CVE-2021-29988)

  - Mozilla developers reported memory safety bugs present in Firefox 90 and Firefox ESR 78.12. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Thunderbird < 78.13, Firefox ESR < 78.13,
    and Firefox < 91. (CVE-2021-29989)

  - Mozilla developers and community members reported memory safety bugs present in Firefox 90. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Firefox < 91. (CVE-2021-29990)

  - Firefox incorrectly accepted a newline in a HTTP/3 header, interpretting it as two separate headers. This
    allowed for a header splitting attack against servers using HTTP/3.  (CVE-2021-29991)

  - crossbeam-deque is a package of work-stealing deques for building task schedulers when programming in
    Rust. In versions prior to 0.7.4 and 0.8.0, the result of the race condition is that one or more tasks in
    the worker queue can be popped twice instead of other tasks that are forgotten and never popped. If tasks
    are allocated on the heap, this can cause double free and a memory leak. If not, this still can cause a
    logical bug. Crates using `Stealer::steal`, `Stealer::steal_batch`, or `Stealer::steal_batch_and_pop` are
    affected by this issue. This has been fixed in crossbeam-deque 0.8.1 and 0.7.4. (CVE-2021-32810)

  - When delegating navigations to the operating system, Firefox would accept the `mk` scheme which might
    allow attackers to launch pages and execute scripts in Internet Explorer in unprivileged mode. This
    bug only affects Firefox for Windows. Other operating systems are unaffected.  (CVE-2021-38492)

  - Mozilla developers Tyson Smith, Christian Holler, and Gabriele Svelto reported memory safety bugs present
    in Thunderbird 78.13.0. Some of these bugs showed evidence of memory corruption and we presume that with
    enough effort some of these could have been exploited to run arbitrary code.  (CVE-2021-38495)

  - During operations on MessageTasks, a task may have been removed while it was still scheduled, resulting in
    memory corruption and a potentially exploitable crash.  (CVE-2021-38496)

  - Through use of reportValidity() and window.open(), a plain-text validation
    message could have been overlaid on another origin, leading to possible user confusion and spoofing
    attacks.  (CVE-2021-38497)

  - During process shutdown, a document could have caused a use-after-free of a languages service object,
    leading to memory corruption and a potentially exploitable crash.  (CVE-2021-38498)

  - Mozilla developers and community members Andreas Pehrson and Christian Holler reported memory safety bugs
    present in Thunderbird 91.1. Some of these bugs showed evidence of memory corruption and we presume that
    with enough effort some of these could have been exploited to run arbitrary code.  (CVE-2021-38500)

  - Mozilla developers and community members Kevin Brosnan, Mihai Alexandru Michis, and Christian Holler
    reported memory safety bugs present in Thunderbird 91.1. Some of these bugs showed evidence of memory
    corruption and we presume that with enough effort some of these could have been exploited to run arbitrary
    code.  (CVE-2021-38501)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188891");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189547");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190269");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191332");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/NOOPOXVWYJPXPZIC3SK7MZFMWSQEQNPG/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b956795");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29980");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29981");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29982");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29983");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29984");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29985");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29986");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29987");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29988");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29990");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29991");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32810");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38492");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38495");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38496");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38497");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38498");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38500");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38501");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38501");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-32810");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-SLE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'MozillaFirefox-91.2.0-8.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'MozillaFirefox-branding-SLE-91-9.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'MozillaFirefox-branding-upstream-91.2.0-8.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'MozillaFirefox-devel-91.2.0-8.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'MozillaFirefox-translations-common-91.2.0-8.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'MozillaFirefox-translations-other-91.2.0-8.54.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'MozillaFirefox / MozillaFirefox-branding-SLE / etc');
}
