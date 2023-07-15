#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-381.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109236);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-6085", "CVE-2018-6086", "CVE-2018-6087", "CVE-2018-6088", "CVE-2018-6089", "CVE-2018-6090", "CVE-2018-6091", "CVE-2018-6092", "CVE-2018-6093", "CVE-2018-6094", "CVE-2018-6095", "CVE-2018-6096", "CVE-2018-6097", "CVE-2018-6098", "CVE-2018-6099", "CVE-2018-6100", "CVE-2018-6101", "CVE-2018-6102", "CVE-2018-6103", "CVE-2018-6104", "CVE-2018-6105", "CVE-2018-6106", "CVE-2018-6107", "CVE-2018-6108", "CVE-2018-6109", "CVE-2018-6110", "CVE-2018-6111", "CVE-2018-6112", "CVE-2018-6113", "CVE-2018-6114", "CVE-2018-6115", "CVE-2018-6116", "CVE-2018-6117");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2018-381)");
  script_summary(english:"Check for the openSUSE-2018-381 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for Chromium to version 66.0.3359.117 fixes the following
issues :

Security issues fixed (boo#1090000) :

  - CVE-2018-6085: Use after free in Disk Cache

  - CVE-2018-6086: Use after free in Disk Cache

  - CVE-2018-6087: Use after free in WebAssembly

  - CVE-2018-6088: Use after free in PDFium

  - CVE-2018-6089: Same origin policy bypass in Service
    Worker

  - CVE-2018-6090: Heap buffer overflow in Skia

  - CVE-2018-6091: Incorrect handling of plug-ins by Service
    Worker

  - CVE-2018-6092: Integer overflow in WebAssembly

  - CVE-2018-6093: Same origin bypass in Service Worker

  - CVE-2018-6094: Exploit hardening regression in Oilpan

  - CVE-2018-6095: Lack of meaningful user interaction
    requirement before file upload

  - CVE-2018-6096: Fullscreen UI spoof

  - CVE-2018-6097: Fullscreen UI spoof

  - CVE-2018-6098: URL spoof in Omnibox

  - CVE-2018-6099: CORS bypass in ServiceWorker

  - CVE-2018-6100: URL spoof in Omnibox

  - CVE-2018-6101: Insufficient protection of remote
    debugging prototol in DevTools 

  - CVE-2018-6102: URL spoof in Omnibox

  - CVE-2018-6103: UI spoof in Permissions

  - CVE-2018-6104: URL spoof in Omnibox

  - CVE-2018-6105: URL spoof in Omnibox

  - CVE-2018-6106: Incorrect handling of promises in V8

  - CVE-2018-6107: URL spoof in Omnibox

  - CVE-2018-6108: URL spoof in Omnibox

  - CVE-2018-6109: Incorrect handling of files by FileAPI

  - CVE-2018-6110: Incorrect handling of plaintext files via
    file:// 

  - CVE-2018-6111: Heap-use-after-free in DevTools

  - CVE-2018-6112: Incorrect URL handling in DevTools

  - CVE-2018-6113: URL spoof in Navigation

  - CVE-2018-6114: CSP bypass

  - CVE-2018-6115: SmartScreen bypass in downloads

  - CVE-2018-6116: Incorrect low memory handling in
    WebAssembly

  - CVE-2018-6117: Confusing autofill settings

  - Various fixes from internal audits, fuzzing and other
    initiatives This update also supports mitigation against
    the Spectre vulnerabilities: 'Strict site isolation' is
    disabled for most users and can be turned on via:
    chrome://flags/#enable-site-per-process This feature is
    undergoing a small percentage trial. Out out of the
    trial is possible via:
    chrome://flags/#site-isolation-trial-opt-out

The following other changes are included :

  - distrust certificates issued by Symantec before
    2016-06-01

  - add option to export saved passwords

  - Reduce videos that auto-play with sound

  - boo#1086199: Fix UI freezing when loading/scaling down
    large images

This update also contains a number of upstream bug fixes and
improvements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090000"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"chromedriver-66.0.3359.117-152.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromedriver-debuginfo-66.0.3359.117-152.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-66.0.3359.117-152.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-debuginfo-66.0.3359.117-152.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-debugsource-66.0.3359.117-152.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromedriver / chromedriver-debuginfo / chromium / etc");
}
