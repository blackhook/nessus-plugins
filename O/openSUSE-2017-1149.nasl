#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1149.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103802);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_name(english:"openSUSE Security Update : libvirt (openSUSE-2017-1149)");
  script_summary(english:"Check for the openSUSE-2017-1149 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libvirt fixes several issues.

This security issue was fixed :

  - bsc#1053600: Escape ssh commed line to prevent
    interpreting malicious hostname as arguments, allowing
    for command execution

These non-security issues were fixed :

  - bsc#1049505, bsc#1051017: Security manager: Don't
    autogenerate seclabels of type 'none' when AppArmor is
    inactive

  - bsc#1052151: Moved /usr/share/libvirt/libvirtLogo.png
    symlink from client to doc subpackage, where its target
    resides

  - bsc#1048783: Ignore newlines in libvirt-guests.sh guest
    list

  - bsc#1031056: Add default controllers for USB devices

  - bsc#1012143: Define path to parted using autoconf cache
    variable. parted is used for management of disk-based
    storage pools

  - bsc#1036785: Prevent output of null target in
    domxml-to-native

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049505"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053600"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-client-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-interface-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-libxl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-libxl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-lxc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-network-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-nodedev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-nwfilter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-qemu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-secret-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-uml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-uml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-vbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-vbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-uml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-vbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-lock-sanlock-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/12");
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

if ( rpm_check(release:"SUSE42.2", reference:"libvirt-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-client-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-client-debuginfo-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-config-network-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-config-nwfilter-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-debuginfo-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-driver-interface-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-driver-interface-debuginfo-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-driver-lxc-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-driver-lxc-debuginfo-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-driver-network-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-driver-network-debuginfo-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-driver-nodedev-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-driver-nodedev-debuginfo-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-driver-nwfilter-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-driver-nwfilter-debuginfo-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-driver-qemu-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-driver-qemu-debuginfo-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-driver-secret-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-driver-secret-debuginfo-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-driver-storage-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-driver-storage-debuginfo-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-driver-uml-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-driver-uml-debuginfo-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-driver-vbox-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-driver-vbox-debuginfo-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-lxc-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-qemu-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-uml-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-daemon-vbox-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-debugsource-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-devel-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-lock-sanlock-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-lock-sanlock-debuginfo-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-nss-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirt-nss-debuginfo-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libvirt-client-32bit-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libvirt-client-debuginfo-32bit-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libvirt-daemon-driver-libxl-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libvirt-daemon-driver-libxl-debuginfo-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libvirt-daemon-xen-2.0.0-13.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libvirt-devel-32bit-2.0.0-13.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-client / libvirt-client-32bit / etc");
}
