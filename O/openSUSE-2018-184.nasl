#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-184.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106916);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-12132", "CVE-2017-8804", "CVE-2018-1000001", "CVE-2018-6485", "CVE-2018-6551");

  script_name(english:"openSUSE Security Update : glibc (openSUSE-2018-184)");
  script_summary(english:"Check for the openSUSE-2018-184 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for glibc fixes the following issues :

Security issues fixed :

  - CVE-2017-8804: Fix memory leak after deserialization
    failure in xdr_bytes, xdr_string (bsc#1037930)

  - CVE-2017-12132: Reduce EDNS payload size to 1200 bytes
    (bsc#1051791)

  - CVE-2018-6485,CVE-2018-6551: Fix integer overflows in
    internal memalign and malloc functions (bsc#1079036)

  - CVE-2018-1000001: Avoid underflow of malloced area
    (bsc#1074293)

Non security bugs fixed :

  - Release read lock after resetting timeout (bsc#1073990)

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037930"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051791"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1073990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079036"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'glibc "realpath()" Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-static-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-i18ndata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-obsolete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-obsolete-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-profile-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nscd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/21");
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

if ( rpm_check(release:"SUSE42.3", reference:"glibc-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-debuginfo-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-debugsource-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-devel-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-devel-debuginfo-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-devel-static-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-extra-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-extra-debuginfo-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-html-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-i18ndata-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-info-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-locale-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-locale-debuginfo-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-obsolete-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-obsolete-debuginfo-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-profile-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-utils-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-utils-debuginfo-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-utils-debugsource-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nscd-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nscd-debuginfo-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"glibc-32bit-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"glibc-debuginfo-32bit-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"glibc-devel-32bit-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"glibc-devel-debuginfo-32bit-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"glibc-devel-static-32bit-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"glibc-locale-32bit-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"glibc-locale-debuginfo-32bit-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"glibc-profile-32bit-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"glibc-utils-32bit-2.22-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"glibc-utils-debuginfo-32bit-2.22-13.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc-utils / glibc-utils-32bit / glibc-utils-debuginfo / etc");
}
