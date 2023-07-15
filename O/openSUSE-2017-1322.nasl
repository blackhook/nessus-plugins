#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1322.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105222);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-15289", "CVE-2017-15597");

  script_name(english:"openSUSE Security Update : xen (openSUSE-2017-1322)");
  script_summary(english:"Check for the openSUSE-2017-1322 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xen to version 4.7.4 (bsc#1027519) fixes several
issues.

This new feature was added :

  - Support migration of HVM domains larger than 1 TB

These security issues were fixed :

  - bsc#1068187: Failure to recognize errors in the Populate
    on Demand (PoD) code allowed for DoS (XSA-246)

  - bsc#1068191: Missing p2m error checking in PoD code
    allowed unprivileged guests to retain a writable mapping
    of freed memory leading to information leaks, privilege
    escalation or DoS (XSA-247).

  - CVE-2017-15289: The mode4and5 write functions allowed
    local OS guest privileged users to cause a denial of
    service (out-of-bounds write access and Qemu process
    crash) via vectors related to dst calculation
    (bsc#1063123)

  - CVE-2017-15597: A grant copy operation being done on a
    grant of a dying domain allowed a malicious guest
    administrator to corrupt hypervisor memory, allowing for
    DoS or potentially privilege escalation and information
    leaks (bsc#1061075).

This non-security issue was fixed :

  - bsc#1055047: Fixed --initrd-inject option in
    virt-install

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068191"
  );
  # https://features.opensuse.org/324052
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE42.2", reference:"xen-debugsource-4.7.4_02-11.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xen-devel-4.7.4_02-11.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xen-libs-4.7.4_02-11.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xen-libs-debuginfo-4.7.4_02-11.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xen-tools-domU-4.7.4_02-11.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xen-tools-domU-debuginfo-4.7.4_02-11.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"xen-4.7.4_02-11.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"xen-doc-html-4.7.4_02-11.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"xen-libs-32bit-4.7.4_02-11.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.7.4_02-11.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"xen-tools-4.7.4_02-11.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"xen-tools-debuginfo-4.7.4_02-11.21.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen-debugsource / xen-devel / xen-libs-32bit / xen-libs / etc");
}
