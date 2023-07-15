#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-661.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100676);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/08");

  script_cve_id(
    "CVE-2017-5070",
    "CVE-2017-5071",
    "CVE-2017-5072",
    "CVE-2017-5073",
    "CVE-2017-5074",
    "CVE-2017-5075",
    "CVE-2017-5076",
    "CVE-2017-5077",
    "CVE-2017-5078",
    "CVE-2017-5079",
    "CVE-2017-5080",
    "CVE-2017-5081",
    "CVE-2017-5082",
    "CVE-2017-5083",
    "CVE-2017-5085",
    "CVE-2017-5086"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2017-661)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update to Chromium 59.0.3071.86 fixes the following security
issues :

  - CVE-2017-5070: Type confusion in V8

  - CVE-2017-5071: Out of bounds read in V8

  - CVE-2017-5072: Address spoofing in Omnibox

  - CVE-2017-5073: Use after free in print preview

  - CVE-2017-5074: Use after free in Apps Bluetooth

  - CVE-2017-5075: Information leak in CSP reporting

  - CVE-2017-5086: Address spoofing in Omnibox

  - CVE-2017-5076: Address spoofing in Omnibox

  - CVE-2017-5077: Heap buffer overflow in Skia

  - CVE-2017-5078: Possible command injection in mailto
    handling

  - CVE-2017-5079: UI spoofing in Blink

  - CVE-2017-5080: Use after free in credit card autofill

  - CVE-2017-5081: Extension verification bypass

  - CVE-2017-5082: Insufficient hardening in credit card
    editor

  - CVE-2017-5083: UI spoofing in Blink

  - CVE-2017-5085: Inappropriate JavaScript execution on
    WebUI pages");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042833");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");

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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"chromedriver-59.0.3071.86-104.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromedriver-debuginfo-59.0.3071.86-104.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromium-59.0.3071.86-104.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromium-debuginfo-59.0.3071.86-104.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromium-debugsource-59.0.3071.86-104.15.1") ) flag++;

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
