#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-e9821afbca.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120875);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2018-16983");
  script_xref(name:"FEDORA", value:"2018-e9821afbca");

  script_name(english:"Fedora 28 : mozilla-noscript (2018-e9821afbca)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Changes since 10.1.8.16: ===

v 10.1.9.6
=============================================================

  - [TB] Gracefully handle legacy external message
    recipients

  - [XSS] Updated known HTML5 events

  - Better IPV6 support

  - UI support for protocol-only entries

v 10.1.9.5
=============================================================

  - Fix for various content script timing related issues
    (thanks therube for reporting)

v 10.1.9.4
=============================================================

  - Prevent total breakages when policies accidentally map
    to invalid match patterns

  - Internal messaging dispatch better coping with multiple
    option windows

  - Avoid multiple CSP DOM insertions

v 10.1.9.3
=============================================================

  - Fixed message handling regression breaking embedders and
    causing potential internal message loops

v 10.1.9.2
=============================================================

  - More efficient window.name-based tab-scoped permissions
    persistence

  - Fixed URL parsing bugs

  - Fixed bug in requestKey generation

  - [Build] Enhanced TLD data update subsystem

  - [UI] CUSTOM presets gets initialized with currently
    applied preset, including temporary/permanent status

  - Improved internal message dispatching, avoiding
    potential race conditions

  - [L10n] Transifex integration

  - Work-around for DOM-injected CSP not being honored when
    appended to the root element, rather than HEAD

  - Transparent support for FQDNs

  - Better file: protocol support

  - Full-page placeholders for media/plugin documents

v 10.1.9.1
=============================================================

  - Fixed NOSCRIPT emulation not running in contexts where
    service workers are disabled, such as private windows
    (thanks Peter Wu for patch)

v 10.1.9 =============================================================

  - Completely revamped CSP backend, enforcing policies both
    in webRequest and in the DOM

  - Reload-less service worker busting

  - removed obsoleted failsafes, including forced reloads

  - Better timing for popup UI feedback on permissions
    changes

  - Send out a 'started' message after initialization to
    help embedders (like the Tor browser) interact with
    NoScript

  - Updated TLDs

v 10.1.8.23
=============================================================

  - Hotfix for reload loops before CSP management
    refactoring

v 10.1.8.22
=============================================================

  - Fixed reload loop on unrestricted tabs (thanks random
    for reporting)

v 10.1.8.20
=============================================================

  - Fixed Sites.domainImplies() misplaced optimization.

  - [L10n] Added Catalan (ca)

v 10.1.8.19
=============================================================

  - Fixed onResponseHeader failing on session restore
    because of onBeforeRequest not having being called.

  - Fixed regression: framed documents' URLs not being
    reported in the UI (thanks xaex for report)

v 10.1.8.18
=============================================================

  - More resilient and optimized Sites.domainImplies()

  - Update ChildPolicies when automatic temp TRUST for
    top-level documents is enabled

  - Fixed messages from content scripts being 'eaten' by the
    wrong dispatcher when UI is open (thanks
    skriptimaahinen)

  - Fixed typo causing accidental permissions/status
    mismatches being checked only while pages are still
    loading (thanks skriptimaahinen)

  - Fixed typo in XSS name sanitization script injection
    (thanks skriptimaahinen)

v 10.1.8.17
=============================================================

  - Fix: Sites.domainImplies() should match subdomains

  - More coherent wrapper around the webex messaging API

  - Fixed inconsistencies affecting ChildPolicies content
    script auto-generated matching rules.

  - Fixed potential issues with cross-process messages

  - Simpler and more reliable safety net to ensure CSP
    headers are injected last among WebExtensions

  - Fixed regression causing refresh loops on pages which
    use type='object' requests to load images, css and other
    types

  - [L10n] ru and de translations

  - [XSS] Updated HTML events auto-generate matching code to
    use both latest Mozilla source code and archived data
    since Firefox ESR 52

  - New dynamic scripts management strategy based on the
    browser.contentScripts API, should fix some elusive,
    likely requestFilter-induced, bugs

  - Fixed no-dot domains threated as empty TLDs (thanks
    Peter Wu for patch)

  - Removed requestFilter hack for dynamic scripts
    management

  - [L10n] br and tr translations (thanks Transifex/OTF,
    https://www.transifex.com/otf/noscript/)

  - Best effort to have webRequest.onHeaderReceived listener
    run last (issue #6, thanks kkapsner)

  - [L10n] Localized 'NoScript Options' title (thanks
    Diklabyte)

  - Fixed inline scripts not being reported to UI (thanks
    skriptimaahinen for patch)

  - Skip non-content windows when deferring startup page
    loads (thanks Rob Wu for reporting)

  - Broader detection of UTF-8 encoding in responses (thanks
    Rob Wu for reporting)

  - Improved support for debugging code removal in releases

  - Fixed startup race condition with pending request
    tracking

  - Fixed updating NoScript reloads tabs with revoked
    temporary permissions.

Legacy version: ===

v 5.1.8.7
=============================================================

  - [Security] Fixed script blocking bypass zero-day (thanks
    Zerodium for unresponsible disclosure,
    https://twitter.com/Zerodium/status/1039127214602641409)

  - [Surrogate] Fixed typo in 2mdn replacement (thansk
    barbaz)

  - [XSS] Fixed InjectionChecker choking at some big JSON
    payloads sents as POST form data

  - [XSS] In-depth protection against native ES6 modules
    abuse

  - Fixed classic beta channel users being accidentally
    migrated to stable (thanks barbaz)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-e9821afbca"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mozilla-noscript package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozilla-noscript");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:28");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^28([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 28", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC28", reference:"mozilla-noscript-10.1.9.6-1.fc28")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla-noscript");
}
