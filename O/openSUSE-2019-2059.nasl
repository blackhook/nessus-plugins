#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2059.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128465);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2019-12155", "CVE-2019-13164", "CVE-2019-14378");

  script_name(english:"openSUSE Security Update : qemu (openSUSE-2019-2059)");
  script_summary(english:"Check for the openSUSE-2019-2059 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for qemu fixes the following issues :

Security issues fixed :

  - CVE-2019-14378: Security fix for heap overflow in
    ip_reass on big packet input (bsc#1143794).

  - CVE-2019-12155: Security fix for NULL pointer
    dereference while releasing spice resources
    (bsc#1135902).

  - CVE-2019-13164: Security fix for qemu-bridge-helper ACL
    can be bypassed when names are too long (bsc#1140402).

Bug fixes and enhancements :

  - Add vcpu features needed for Cascadelake-Server,
    Icelake-Client and Icelake-Server, especially the
    foundational arch-capabilities to help with security and
    performance on Intel hosts (bsc#1134883) (fate#327764)

  - Add support for one more security/performance related
    vcpu feature (bsc#1136778) (fate#327796)

  - Disable file locking in the Xen PV disk backend to avoid
    locking issues with PV domUs during migration. The
    issues triggered by the locking can not be properly
    handled in libxl. The locking introduced in qemu-2.10
    was removed again in qemu-4.0 (bsc#1079730, bsc#1098403,
    bsc#1111025).

  - Ignore csske for expanding the cpu model (bsc#1136540)

  - Fix vm migration is failing with input/output error when
    nfs server is disconnected (bsc#1119115)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140402"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1143794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/327764"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/327796"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-arm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-dmg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-dmg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-gluster-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-iscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-ssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ipxe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ksm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ppc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-s390-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-vgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-x86-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/03");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"qemu-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-arm-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-arm-debuginfo-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-curl-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-curl-debuginfo-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-dmg-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-dmg-debuginfo-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-gluster-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-gluster-debuginfo-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-iscsi-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-iscsi-debuginfo-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-rbd-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-rbd-debuginfo-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-ssh-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-ssh-debuginfo-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-debuginfo-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-debugsource-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-extra-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-extra-debuginfo-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-guest-agent-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-guest-agent-debuginfo-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-ipxe-1.0.0+-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-ksm-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-kvm-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-lang-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-ppc-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-ppc-debuginfo-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-s390-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-s390-debuginfo-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-seabios-1.11.0-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-sgabios-8-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-tools-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-tools-debuginfo-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-vgabios-1.11.0-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-x86-2.11.2-lp150.7.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-x86-debuginfo-2.11.2-lp150.7.25.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu / qemu-arm / qemu-arm-debuginfo / qemu-block-curl / etc");
}
