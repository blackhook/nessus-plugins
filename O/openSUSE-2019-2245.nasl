#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2245.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(129580);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/01");

  script_cve_id("CVE-2019-5736");

  script_name(english:"openSUSE Security Update : lxc (openSUSE-2019-2245)");
  script_summary(english:"Check for the openSUSE-2019-2245 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for lxc fixes the following issues :

Update to lxc 3.2.1. The changelog can be found at

https://discuss.linuxcontainers.org/t/lxc-3-2-1-has-been-released/5322

  + seccomp: support syscall forwarding to userspace

  + add lxc.seccomp.allow_nesting

  + pidfd: Add initial support for the new pidfd api

  - Many hardening improvements.

  - Use /sys/kernel/cgroup/delegate file for cgroup v2.

  - Fix CVE-2019-5736 equivalent bug.

  - fix apparmor dropin to be compatible with LXC 3.1.0
    (boo#1131762)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://discuss.linuxcontainers.org/t/lxc-3-2-1-has-been-released/5322"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected lxc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Docker Container Escape Via runC Overwrite');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblxc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblxc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblxc1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lxc-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lxc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lxc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_cgfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_cgfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/04");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"liblxc-devel-3.2.1-lp151.4.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"liblxc1-3.2.1-lp151.4.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"liblxc1-debuginfo-3.2.1-lp151.4.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lxc-3.2.1-lp151.4.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lxc-bash-completion-3.2.1-lp151.4.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lxc-debuginfo-3.2.1-lp151.4.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"lxc-debugsource-3.2.1-lp151.4.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pam_cgfs-3.2.1-lp151.4.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pam_cgfs-debuginfo-3.2.1-lp151.4.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "liblxc-devel / liblxc1 / liblxc1-debuginfo / lxc / etc");
}
