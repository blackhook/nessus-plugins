#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-762.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149891);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/11");

  script_cve_id("CVE-2021-30506", "CVE-2021-30507", "CVE-2021-30508", "CVE-2021-30509", "CVE-2021-30510", "CVE-2021-30511", "CVE-2021-30512", "CVE-2021-30513", "CVE-2021-30514", "CVE-2021-30515", "CVE-2021-30516", "CVE-2021-30517", "CVE-2021-30518", "CVE-2021-30519", "CVE-2021-30520");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2021-762)");
  script_summary(english:"Check for the openSUSE-2021-762 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for chromium fixes the following issues :

(This is a rerelease with aarch64 enabled.)

Chromium 90.0.4430.212 (boo#1185908)

  - CVE-2021-30506: Incorrect security UI in Web App
    Installs

  - CVE-2021-30507: Inappropriate implementation in Offline

  - CVE-2021-30508: Heap buffer overflow in Media Feeds

  - CVE-2021-30509: Out of bounds write in Tab Strip

  - CVE-2021-30510: Race in Aura

  - CVE-2021-30511: Out of bounds read in Tab Group

  - CVE-2021-30512: Use after free in Notifications

  - CVE-2021-30513: Type Confusion in V8

  - CVE-2021-30514: Use after free in Autofill

  - CVE-2021-30515: Use after free in File API

  - CVE-2021-30516: Heap buffer overflow in History

  - CVE-2021-30517: Type Confusion in V8

  - CVE-2021-30518: Heap buffer overflow in Reader Mode

  - CVE-2021-30519: Use after free in Payments

  - CVE-2021-30520: Use after free in Tab Strip

  - FTP support disabled at runtime by default since release
    88. Chromium 91 will remove support for ftp altogether
    (boo#1185496)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185716"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185908"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30520");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"chromedriver-90.0.4430.212-lp152.2.95.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromedriver-debuginfo-90.0.4430.212-lp152.2.95.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromium-90.0.4430.212-lp152.2.95.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromium-debuginfo-90.0.4430.212-lp152.2.95.1", allowmaj:TRUE) ) flag++;

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
