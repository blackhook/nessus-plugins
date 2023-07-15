#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-825.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101760);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-10971", "CVE-2017-10972");

  script_name(english:"openSUSE Security Update : xorg-x11-server (openSUSE-2017-825)");
  script_summary(english:"Check for the openSUSE-2017-825 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xorg-x11-server fixes the following issues :

  - CVE-2017-10971: Fix endianess handling of GenericEvent
    to prevent a stack overflow by clients. (bnc#1035283)

  - Make sure the type of all events to be sent by
    ProcXSendExtensionEvent are in the allowed range.

  - CVE-2017-10972: Initialize the xEvent eventT with zeros
    to avoid information leakage.

  - Improve retrieval of entropy for generating random
    authentication cookies (boo#1025084)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1035283"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/17");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"xorg-x11-server-7.6_1.18.3-12.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xorg-x11-server-debuginfo-7.6_1.18.3-12.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xorg-x11-server-debugsource-7.6_1.18.3-12.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xorg-x11-server-extra-7.6_1.18.3-12.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xorg-x11-server-extra-debuginfo-7.6_1.18.3-12.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xorg-x11-server-sdk-7.6_1.18.3-12.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xorg-x11-server-source-7.6_1.18.3-12.20.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-server / xorg-x11-server-debuginfo / etc");
}
