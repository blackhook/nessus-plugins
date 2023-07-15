#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-553.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(136010);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/30");

  script_cve_id("CVE-2019-13456", "CVE-2019-17185");

  script_name(english:"openSUSE Security Update : freeradius-server (openSUSE-2020-553)");
  script_summary(english:"Check for the openSUSE-2020-553 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for freeradius-server fixes the following issues :

  - CVE-2019-13456: Fixed a side-channel password leak in
    EAP-pwd (bsc#1144524).

  - CVE-2019-17185: Fixed a debial of service due to
    multithreaded BN_CTX access (bsc#1166847).

  - Fixed an issue in TLS-EAP where the OCSP verification,
    when an intermediate client certificate was not
    explicitly trusted (bsc#1146848).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166847"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freeradius-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13456");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"freeradius-server-3.0.16-lp151.4.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freeradius-server-debuginfo-3.0.16-lp151.4.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freeradius-server-debugsource-3.0.16-lp151.4.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freeradius-server-devel-3.0.16-lp151.4.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freeradius-server-krb5-3.0.16-lp151.4.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freeradius-server-krb5-debuginfo-3.0.16-lp151.4.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freeradius-server-ldap-3.0.16-lp151.4.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freeradius-server-ldap-debuginfo-3.0.16-lp151.4.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freeradius-server-libs-3.0.16-lp151.4.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freeradius-server-libs-debuginfo-3.0.16-lp151.4.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freeradius-server-mysql-3.0.16-lp151.4.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freeradius-server-mysql-debuginfo-3.0.16-lp151.4.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freeradius-server-perl-3.0.16-lp151.4.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freeradius-server-perl-debuginfo-3.0.16-lp151.4.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freeradius-server-postgresql-3.0.16-lp151.4.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freeradius-server-postgresql-debuginfo-3.0.16-lp151.4.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freeradius-server-python-3.0.16-lp151.4.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freeradius-server-python-debuginfo-3.0.16-lp151.4.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freeradius-server-sqlite-3.0.16-lp151.4.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freeradius-server-sqlite-debuginfo-3.0.16-lp151.4.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freeradius-server-utils-3.0.16-lp151.4.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freeradius-server-utils-debuginfo-3.0.16-lp151.4.4.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freeradius-server / freeradius-server-debuginfo / etc");
}
