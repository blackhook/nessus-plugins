#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-697.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79423);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_name(english:"openSUSE Security Update : openssl (openSUSE-SU-2014:1474-1)");
  script_summary(english:"Check for the openSUSE-2014-697 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This openssl update fixes a TLS handshake problem when elliptic curves
are in use."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=905037"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2014-11/msg00085.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-hmac-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"libopenssl-devel-1.0.1j-1.71.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libopenssl1_0_0-1.0.1j-1.71.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libopenssl1_0_0-debuginfo-1.0.1j-1.71.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openssl-1.0.1j-1.71.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openssl-debuginfo-1.0.1j-1.71.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openssl-debugsource-1.0.1j-1.71.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libopenssl-devel-32bit-1.0.1j-1.71.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libopenssl1_0_0-32bit-1.0.1j-1.71.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.1j-1.71.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libopenssl-devel-1.0.1j-11.59.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libopenssl1_0_0-1.0.1j-11.59.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libopenssl1_0_0-debuginfo-1.0.1j-11.59.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openssl-1.0.1j-11.59.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openssl-debuginfo-1.0.1j-11.59.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openssl-debugsource-1.0.1j-11.59.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libopenssl-devel-32bit-1.0.1j-11.59.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libopenssl1_0_0-32bit-1.0.1j-11.59.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.1j-11.59.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libopenssl-devel-1.0.1j-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libopenssl1_0_0-1.0.1j-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libopenssl1_0_0-debuginfo-1.0.1j-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libopenssl1_0_0-hmac-1.0.1j-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"openssl-1.0.1j-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"openssl-debuginfo-1.0.1j-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"openssl-debugsource-1.0.1j-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libopenssl-devel-32bit-1.0.1j-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libopenssl1_0_0-32bit-1.0.1j-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.1j-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libopenssl1_0_0-hmac-32bit-1.0.1j-2.10.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl");
}
