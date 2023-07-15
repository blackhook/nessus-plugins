#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-139.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106663);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-9780", "CVE-2018-6560");

  script_name(english:"openSUSE Security Update : flatpak (openSUSE-2018-139)");
  script_summary(english:"Check for the openSUSE-2018-139 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for flatpak to version 0.8.9 fixes security issues and
bugs.

The following vulnerabilities were fixed :

  - CVE-2018-6560: sandbox escape in the flatpak dbus proxy
    (boo#1078923)

  - CVE-2017-9780: Malicious apps could have included
    inappropriate permissions (boo#1078989)

  - old-style eavesdropping in the dbus proxy (boo#1078993)

This update also includes all upstream improvements and fixes in this
stable release series."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078993"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected flatpak packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flatpak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flatpak-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flatpak-builder-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flatpak-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flatpak-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flatpak-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libflatpak0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libflatpak0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-Flatpak-1_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE42.3", reference:"flatpak-0.8.9-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"flatpak-builder-0.8.9-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"flatpak-builder-debuginfo-0.8.9-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"flatpak-debuginfo-0.8.9-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"flatpak-debugsource-0.8.9-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"flatpak-devel-0.8.9-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libflatpak0-0.8.9-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libflatpak0-debuginfo-0.8.9-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"typelib-1_0-Flatpak-1_0-0.8.9-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "flatpak / flatpak-builder / flatpak-builder-debuginfo / etc");
}
