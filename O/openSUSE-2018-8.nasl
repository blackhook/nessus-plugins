#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-8.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105641);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-5715");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"openSUSE Security Update : qemu (openSUSE-2018-8) (Spectre)");
  script_summary(english:"Check for the openSUSE-2018-8 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for qemu fixes the following issues :

A new feature was added :

  - Support EPYC vCPU type (bsc#1052825 fate#324038)

Also a mitigation for a security problem has been applied :

  - CVE-2017-5715: QEMU was updated to allow passing through
    new MSR and CPUID flags from the host VM to the CPU, to
    allow enabling/disabling branch prediction features in
    the Intel CPU. (bsc#1068032)

This update was imported from the SUSE:SLE-12-SP3:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068032"
  );
  # https://features.opensuse.org/324038
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-arm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-dmg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-dmg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-iscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-ssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ipxe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ksm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ppc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-s390-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-vgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-x86-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/08");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if ( rpm_check(release:"SUSE42.3", reference:"qemu-ipxe-1.0.0-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qemu-linux-user-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qemu-linux-user-debuginfo-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qemu-linux-user-debugsource-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qemu-seabios-1.10.2-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qemu-sgabios-8-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qemu-vgabios-1.10.2-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-arm-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-arm-debuginfo-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-curl-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-curl-debuginfo-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-dmg-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-dmg-debuginfo-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-iscsi-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-iscsi-debuginfo-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-rbd-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-rbd-debuginfo-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-ssh-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-ssh-debuginfo-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-debugsource-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-extra-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-extra-debuginfo-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-guest-agent-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-guest-agent-debuginfo-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-ksm-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-kvm-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-lang-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-ppc-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-ppc-debuginfo-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-s390-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-s390-debuginfo-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-testsuite-2.9.1-38.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-tools-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-tools-debuginfo-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-x86-2.9.1-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-x86-debuginfo-2.9.1-38.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-linux-user / qemu-linux-user-debuginfo / etc");
}
