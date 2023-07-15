#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-668.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149636);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/20");

  script_cve_id("CVE-2021-25214", "CVE-2021-25215");

  script_name(english:"openSUSE Security Update : bind (openSUSE-2021-668)");
  script_summary(english:"Check for the openSUSE-2021-668 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for bind fixes the following issues :

  - CVE-2021-25214: Fixed a broken inbound incremental zone
    update (IXFR) which could have caused named to terminate
    unexpectedly (bsc#1185345).

  - CVE-2021-25215: Fixed an assertion check which could
    have failed while answering queries for DNAME records
    that required the DNAME to be processed to resolve
    itself (bsc#1185345).

  - make /usr/bin/delv in bind-tools position independent
    (bsc#1183453).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183453"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185345"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-chrootenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbind9-1600");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbind9-1600-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbind9-1600-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbind9-1600-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdns1605");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdns1605-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdns1605-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdns1605-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libirs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libirs1601");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libirs1601-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libirs1601-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libirs1601-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisc1606");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisc1606-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisc1606-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisc1606-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisccc1600");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisccc1600-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisccc1600-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisccc1600-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisccfg1600");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisccfg1600-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisccfg1600-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisccfg1600-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libns1604");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libns1604-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libns1604-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libns1604-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-bind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"bind-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bind-chrootenv-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bind-debuginfo-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bind-debugsource-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bind-devel-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bind-utils-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bind-utils-debuginfo-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libbind9-1600-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libbind9-1600-debuginfo-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libdns1605-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libdns1605-debuginfo-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libirs-devel-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libirs1601-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libirs1601-debuginfo-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libisc1606-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libisc1606-debuginfo-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libisccc1600-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libisccc1600-debuginfo-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libisccfg1600-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libisccfg1600-debuginfo-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libns1604-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libns1604-debuginfo-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-bind-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"bind-devel-32bit-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libbind9-1600-32bit-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libbind9-1600-32bit-debuginfo-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libdns1605-32bit-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libdns1605-32bit-debuginfo-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libirs1601-32bit-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libirs1601-32bit-debuginfo-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libisc1606-32bit-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libisc1606-32bit-debuginfo-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libisccc1600-32bit-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libisccc1600-32bit-debuginfo-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libisccfg1600-32bit-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libisccfg1600-32bit-debuginfo-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libns1604-32bit-9.16.6-lp152.14.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libns1604-32bit-debuginfo-9.16.6-lp152.14.19.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chrootenv / bind-debuginfo / bind-debugsource / etc");
}
