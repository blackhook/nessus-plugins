#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-264.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108436);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/08");

  script_cve_id(
    "CVE-2017-11215",
    "CVE-2017-11225",
    "CVE-2018-6057",
    "CVE-2018-6060",
    "CVE-2018-6061",
    "CVE-2018-6062",
    "CVE-2018-6063",
    "CVE-2018-6064",
    "CVE-2018-6065",
    "CVE-2018-6066",
    "CVE-2018-6067",
    "CVE-2018-6068",
    "CVE-2018-6069",
    "CVE-2018-6070",
    "CVE-2018-6071",
    "CVE-2018-6072",
    "CVE-2018-6073",
    "CVE-2018-6074",
    "CVE-2018-6075",
    "CVE-2018-6076",
    "CVE-2018-6077",
    "CVE-2018-6078",
    "CVE-2018-6079",
    "CVE-2018-6080",
    "CVE-2018-6081",
    "CVE-2018-6082",
    "CVE-2018-6083"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"openSUSE Security Update : Chromium (openSUSE-2018-264)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for Chromium to version 65.0.3325.162 fixes the following
issues :

  - CVE-2017-11215: Use after free in Flash

  - CVE-2017-11225: Use after free in Flash

  - CVE-2018-6060: Use after free in Blink

  - CVE-2018-6061: Race condition in V8

  - CVE-2018-6062: Heap buffer overflow in Skia

  - CVE-2018-6057: Incorrect permissions on shared memory

  - CVE-2018-6063: Incorrect permissions on shared memory

  - CVE-2018-6064: Type confusion in V8

  - CVE-2018-6065: Integer overflow in V8

  - CVE-2018-6066: Same Origin Bypass via canvas

  - CVE-2018-6067: Buffer overflow in Skia

  - CVE-2018-6068: Object lifecycle issues in Chrome Custom
    Tab

  - CVE-2018-6069: Stack-based buffer overflow in Skia

  - CVE-2018-6070: CSP bypass through extensions

  - CVE-2018-6071: Heap bufffer overflow in Skia

  - CVE-2018-6072: Integer overflow in PDFium

  - CVE-2018-6073: Heap bufffer overflow in WebGL

  - CVE-2018-6074: Mark-of-the-Web bypass

  - CVE-2018-6075: Overly permissive cross origin downloads

  - CVE-2018-6076: Incorrect handling of URL fragment
    identifiers in Blink

  - CVE-2018-6077: Timing attack using SVG filters

  - CVE-2018-6078: URL Spoof in OmniBox

  - CVE-2018-6079: Information disclosure via texture data
    in WebGL

  - CVE-2018-6080: Information disclosure in IPC call

  - CVE-2018-6081: XSS in interstitials

  - CVE-2018-6082: Circumvention of port blocking

  - CVE-2018-6083: Incorrect processing of AppManifests");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084296");
  script_set_attribute(attribute:"solution", value:
"Update the affected Chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE42.3", reference:"chromedriver-65.0.3325.162-146.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromedriver-debuginfo-65.0.3325.162-146.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-65.0.3325.162-146.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-debuginfo-65.0.3325.162-146.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-debugsource-65.0.3325.162-146.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromedriver / chromedriver-debuginfo / chromium / etc");
}
