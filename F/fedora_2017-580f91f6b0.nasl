#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-580f91f6b0.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104757);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-5092", "CVE-2017-5093", "CVE-2017-5095", "CVE-2017-5097", "CVE-2017-5099", "CVE-2017-5102", "CVE-2017-5103", "CVE-2017-5107", "CVE-2017-5112", "CVE-2017-5114", "CVE-2017-5117", "CVE-2017-5118");
  script_xref(name:"FEDORA", value:"2017-580f91f6b0");

  script_name(english:"Fedora 25 : qt5-qtwebengine (2017-580f91f6b0)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update of QtWebEngine to the security and bugfix release 5.9.2,
including :

Chromium Snapshot :

  - Security fixes from Chromium up to version 61.0.3163.79
    Including: CVE-2017-5092, CVE-2017-5093, CVE-2017-5095,
    CVE-2017-5097, CVE-2017-5099, CVE-2017-5102,
    CVE-2017-5103, CVE-2017-5107, CVE-2017-5112,
    CVE-2017-5114, CVE-2017-5117 and CVE-2017-5118

  - Fixed Skia to to render text correctly with FreeType
    2.8.1

  - [QTBUG-50389] Fixed assert on some flash content

QtWebEngine :

  - [QTBUG-57505] Handle --force-webrtc-ip-handling-policy
    on command-line

  - [QTBUG-58306] Fixed handling of menu key

  - [QTBUG-60790] Fixed dragging images to desktop

  - [QTBUG-61354] Set referrer on download requests

  - [QTBUG-61429] Fixed cancelling IME composition

  - [QTBUG-61506] Stop searching when navigating away

  - [QTBUG-61910] Fixed an issue where system proxy settings
    were not picked up correctly

  - [QTBUG-62112] Fixed upside-down rendering in software
    rendering mode

  - [QTBUG-62112] Fixed rendering of content with
    preserve-3d in CSS

  - [QTBUG-62311] Fixed hang when exiting with open combobox

  - [QTBUG-62808] Handle --explicitly-allowed-ports on
    command-line

  - [QTBUG-62898] Fixed accessing webchannels from
    document-creation user-scripts after navigation.

  - [QTBUG-62942] Fixed committing IME composition on touch
    events

QWebEngineView :

  - [QTBUG-61621] Fixed propagation of unhandled key press
    events

WebEngineView :

  - The callback version of printToPdf is now called with a
    proper bytearray result instead of a PDF data in a
    JavaScript string.

Platform Specific Changes :

  - [QTBUG-61528, QTBUG-62673] Fixed various multilib build
    configurations

  - [QTBUG-61846] Fixed host builds on Arm and MIPS

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-580f91f6b0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qt5-qtwebengine package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtwebengine");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:25");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^25([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 25", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC25", reference:"qt5-qtwebengine-5.9.2-2.fc25")) flag++;


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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qt5-qtwebengine");
}
