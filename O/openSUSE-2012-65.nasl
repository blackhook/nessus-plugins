#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-65.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74767);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2011-2203", "CVE-2011-4604", "CVE-2012-0056", "CVE-2012-0207");

  script_name(english:"openSUSE Security Update : kernel (openSUSE-2012-65)");
  script_summary(english:"Check for the openSUSE-2012-65 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 12.1 kernel was updated to 3.1.9 to fix bugs and security
issues. The full list of changes in 3.1.9 is available here :

http://www.kernel.org/pub/linux/kernel/v3.0/ChangeLog-3.1.9
http://www.kernel.org/pub/linux/kernel/v3.0/ChangeLog-3.1.8
http://www.kernel.org/pub/linux/kernel/v3.0/ChangeLog-3.1.7
http://www.kernel.org/pub/linux/kernel/v3.0/ChangeLog-3.1.6
http://www.kernel.org/pub/linux/kernel/v3.0/ChangeLog-3.1.5
http://www.kernel.org/pub/linux/kernel/v3.0/ChangeLog-3.1.4
http://www.kernel.org/pub/linux/kernel/v3.0/ChangeLog-3.1.3
http://www.kernel.org/pub/linux/kernel/v3.0/ChangeLog-3.1.2
http://www.kernel.org/pub/linux/kernel/v3.0/ChangeLog-3.1.2 

Following security issues have been fixed :

CVE-2011-2203: Missing NULL pointer check in hfs filesystem code

CVE-2011-4604: Fix possible kernel memory corruption if B.A.T.M.A.N.
mesh protocol is being used.

CVE-2012-0056: Local root vulnerability via writing to /proc/pid/mem

CVE-2012-0207: Remote DoS vulnerability via crafted IGMP packages.

Following non-security bug fixes have been added :

  - BTRFS support has been improved with many bug fixes."
  );
  # http://www.kernel.org/pub/linux/kernel/v3.0/ChangeLog-3.1.2
  script_set_attribute(
    attribute:"see_also",
    value:"https://mirrors.edge.kernel.org/pub/linux/kernel/v3.0/ChangeLog-3.1.2"
  );
  # http://www.kernel.org/pub/linux/kernel/v3.0/ChangeLog-3.1.3
  script_set_attribute(
    attribute:"see_also",
    value:"https://mirrors.edge.kernel.org/pub/linux/kernel/v3.0/ChangeLog-3.1.3"
  );
  # http://www.kernel.org/pub/linux/kernel/v3.0/ChangeLog-3.1.4
  script_set_attribute(
    attribute:"see_also",
    value:"https://mirrors.edge.kernel.org/pub/linux/kernel/v3.0/ChangeLog-3.1.4"
  );
  # http://www.kernel.org/pub/linux/kernel/v3.0/ChangeLog-3.1.5
  script_set_attribute(
    attribute:"see_also",
    value:"https://mirrors.edge.kernel.org/pub/linux/kernel/v3.0/ChangeLog-3.1.5"
  );
  # http://www.kernel.org/pub/linux/kernel/v3.0/ChangeLog-3.1.6
  script_set_attribute(
    attribute:"see_also",
    value:"https://mirrors.edge.kernel.org/pub/linux/kernel/v3.0/ChangeLog-3.1.6"
  );
  # http://www.kernel.org/pub/linux/kernel/v3.0/ChangeLog-3.1.7
  script_set_attribute(
    attribute:"see_also",
    value:"https://mirrors.edge.kernel.org/pub/linux/kernel/v3.0/ChangeLog-3.1.7"
  );
  # http://www.kernel.org/pub/linux/kernel/v3.0/ChangeLog-3.1.8
  script_set_attribute(
    attribute:"see_also",
    value:"https://mirrors.edge.kernel.org/pub/linux/kernel/v3.0/ChangeLog-3.1.8"
  );
  # http://www.kernel.org/pub/linux/kernel/v3.0/ChangeLog-3.1.9
  script_set_attribute(
    attribute:"see_also",
    value:"https://mirrors.edge.kernel.org/pub/linux/kernel/v3.0/ChangeLog-3.1.9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=672923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=679059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=689860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=691052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=698540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=699709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=724616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=724620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=724734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=726296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=727348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=730103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=730731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=731261"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=736149"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=737624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=740118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=742279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=742322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=743608"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-base-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-base-debuginfo-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-debuginfo-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-debugsource-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-devel-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-devel-debuginfo-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-base-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-base-debuginfo-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-debuginfo-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-debugsource-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-devel-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-devel-debuginfo-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-base-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-base-debuginfo-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-debuginfo-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-debugsource-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-devel-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-devel-debuginfo-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-devel-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-base-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-base-debuginfo-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-debuginfo-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-debugsource-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-devel-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-devel-debuginfo-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-extra-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-extra-debuginfo-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-base-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-base-debuginfo-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-debuginfo-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-debugsource-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-devel-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-devel-debuginfo-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-source-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-source-vanilla-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-syms-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-base-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-base-debuginfo-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-debuginfo-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-debugsource-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-devel-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-devel-debuginfo-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-base-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-base-debuginfo-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-debuginfo-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-debugsource-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-devel-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-devel-debuginfo-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-base-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-base-debuginfo-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-debuginfo-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-debugsource-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-devel-3.1.9-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-devel-debuginfo-3.1.9-1.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
