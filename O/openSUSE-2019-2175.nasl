#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2175.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129341);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_name(english:"openSUSE Security Update : util-linux and shadow (openSUSE-2019-2175)");
  script_summary(english:"Check for the openSUSE-2019-2175 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for util-linux and shadow fixes the following issues :

util-linux :

  - Fixed an issue where PATH settings in /etc/default/su
    being ignored (bsc#1121197)

  - Prevent outdated pam files (bsc#1082293).

  - Do not trim read-only volumes (bsc#1106214).

  - Integrate pam_keyinit pam module to login (bsc#1081947).

  - Perform one-time reset of /etc/default/su (bsc#1121197).

  - Fix problems in reading of login.defs values
    (bsc#1121197)

  - libmount: To prevent incorrect behavior, recognize more
    pseudofs and netfs (bsc#1122417).

  - raw.service: Add RemainAfterExit=yes (bsc#1135534).

  - agetty: Return previous response of agetty for special
    characters (bsc#1085196, bsc#1125886)

  - Fix /etc/default/su comments and create
    /etc/default/runuser (bsc#1121197).

shadow :

  - Fixed an issue where PATH settings in /etc/default/su
    being ignored (bsc#1121197)

  - Hardening for su wrappers (bsc#353876)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085196"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135534"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=353876"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected util-linux and shadow packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdisk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdisk-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdisk1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdisk1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:shadow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:shadow-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:shadow-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"libblkid-devel-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libblkid-devel-static-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libblkid1-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libblkid1-debuginfo-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libfdisk-devel-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libfdisk-devel-static-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libfdisk1-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libfdisk1-debuginfo-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libmount-devel-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libmount-devel-static-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libmount1-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libmount1-debuginfo-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsmartcols-devel-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsmartcols-devel-static-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsmartcols1-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsmartcols1-debuginfo-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libuuid-devel-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libuuid-devel-static-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libuuid1-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libuuid1-debuginfo-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"shadow-4.5-lp150.11.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"shadow-debuginfo-4.5-lp150.11.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"shadow-debugsource-4.5-lp150.11.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"util-linux-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"util-linux-debuginfo-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"util-linux-debugsource-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"util-linux-lang-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libblkid-devel-32bit-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libblkid1-32bit-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libblkid1-32bit-debuginfo-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libmount-devel-32bit-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libmount1-32bit-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libmount1-32bit-debuginfo-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libuuid-devel-32bit-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libuuid1-32bit-2.31.1-lp150.7.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libuuid1-32bit-debuginfo-2.31.1-lp150.7.10.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "shadow / shadow-debuginfo / shadow-debugsource / libblkid-devel / etc");
}
