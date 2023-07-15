#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-805.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111567);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-7738");

  script_name(english:"openSUSE Security Update : util-linux (openSUSE-2018-805)");
  script_summary(english:"Check for the openSUSE-2018-805 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for util-linux fixes the following issues :

This non-security issue was fixed :

  - CVE-2018-7738: bash-completion/umount allowed local
    users to gain privileges by embedding shell commands in
    a mountpoint name, which was mishandled during a umount
    command by a different user (bsc#1084300).

These non-security issues were fixed :

  - Fixed crash loop in lscpu (bsc#1072947).

  - Fixed possible segfault of umount -a

  - Fixed mount -a on NFS bind mounts (bsc#1080740).

  - Fixed lsblk on NVMe (bsc#1078662).

This update was imported from the SUSE:SLE-12-SP3:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1072947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084300"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected util-linux packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdisk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdisk-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdisk1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdisk1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libmount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libmount-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libmount-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-systemd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:uuidd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:uuidd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/07");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"libblkid-devel-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libblkid-devel-static-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libblkid1-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libblkid1-debuginfo-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libfdisk-devel-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libfdisk-devel-static-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libfdisk1-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libfdisk1-debuginfo-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmount-devel-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmount-devel-static-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmount1-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmount1-debuginfo-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsmartcols-devel-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsmartcols-devel-static-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsmartcols1-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsmartcols1-debuginfo-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libuuid-devel-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libuuid-devel-static-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libuuid1-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libuuid1-debuginfo-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-libmount-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-libmount-debuginfo-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-libmount-debugsource-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"util-linux-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"util-linux-debuginfo-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"util-linux-debugsource-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"util-linux-lang-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"util-linux-systemd-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"util-linux-systemd-debuginfo-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"util-linux-systemd-debugsource-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"uuidd-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"uuidd-debuginfo-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libblkid-devel-32bit-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libblkid1-32bit-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libblkid1-debuginfo-32bit-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmount-devel-32bit-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmount1-32bit-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmount1-debuginfo-32bit-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libuuid-devel-32bit-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libuuid1-32bit-2.29.2-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libuuid1-debuginfo-32bit-2.29.2-8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-libmount / python-libmount-debuginfo / etc");
}
