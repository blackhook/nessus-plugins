#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-475.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99426);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-7392", "CVE-2017-7393", "CVE-2017-7394", "CVE-2017-7395", "CVE-2017-7396");

  script_name(english:"openSUSE Security Update : tigervnc (openSUSE-2017-475)");
  script_summary(english:"Check for the openSUSE-2017-475 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for tigervnc provides the several fixes.

These security issues were fixed :

  - CVE-2017-7392, CVE-2017-7396: Client can cause leak in
    VNC server (bsc#1031886)

  - CVE-2017-7395: Authenticated VNC client can crash VNC
    server (bsc#1031877)

  - CVE-2017-7394: Client can crash or block VNC server
    (bsc#1031879)

  - CVE-2017-7393: Authenticated client can cause double
    free in VNC server (bsc#1031875)

  - Prevent buffer overflow in VNC client, allowing for
    crashing the client (bnc#1032880)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032880"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tigervnc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvnc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvnc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvnc1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tigervnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tigervnc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tigervnc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-Xvnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-Xvnc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"tigervnc-1.5.0-40.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tigervnc-debuginfo-1.5.0-40.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tigervnc-debugsource-1.5.0-40.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xorg-x11-Xvnc-1.5.0-40.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xorg-x11-Xvnc-debuginfo-1.5.0-40.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libXvnc-devel-1.6.0-16.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libXvnc1-1.6.0-16.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libXvnc1-debuginfo-1.6.0-16.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tigervnc-1.6.0-16.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tigervnc-debuginfo-1.6.0-16.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tigervnc-debugsource-1.6.0-16.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xorg-x11-Xvnc-1.6.0-16.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xorg-x11-Xvnc-debuginfo-1.6.0-16.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tigervnc / tigervnc-debuginfo / tigervnc-debugsource / etc");
}
