#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-821.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(150183);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/07");

  script_cve_id("CVE-2021-31215");

  script_name(english:"openSUSE Security Update : slurm (openSUSE-2021-821)");
  script_summary(english:"Check for the openSUSE-2021-821 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for slurm fixes the following issues :

  - CVE-2021-31215: Fixed a environment mishandling that
    allowed remote code execution as SlurmUser
    (bsc#1186024).

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1186024"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected slurm packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnss_slurm2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnss_slurm2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpmi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpmi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libslurm35");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libslurm35-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-slurm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-auth-none");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-auth-none-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-config-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-cray");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-cray-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-hdf5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-hdf5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-lua-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-munge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-munge-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-node-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-openlava");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-pam_slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-pam_slurm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-rest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-rest-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-seff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-sjstat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-slurmdbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-slurmdbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-sql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-sview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-sview-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-torque");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-torque-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-webdoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/03");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"libnss_slurm2-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libnss_slurm2-debuginfo-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libpmi0-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libpmi0-debuginfo-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libslurm35-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libslurm35-debuginfo-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"perl-slurm-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"perl-slurm-debuginfo-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-auth-none-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-auth-none-debuginfo-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-config-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-config-man-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-cray-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-cray-debuginfo-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-debuginfo-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-debugsource-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-devel-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-hdf5-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-hdf5-debuginfo-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-lua-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-lua-debuginfo-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-munge-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-munge-debuginfo-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-node-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-node-debuginfo-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-openlava-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-pam_slurm-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-pam_slurm-debuginfo-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-plugins-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-plugins-debuginfo-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-rest-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-rest-debuginfo-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-seff-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-sjstat-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-slurmdbd-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-slurmdbd-debuginfo-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-sql-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-sql-debuginfo-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-sview-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-sview-debuginfo-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-torque-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-torque-debuginfo-20.02.7-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-webdoc-20.02.7-lp152.2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libnss_slurm2 / libnss_slurm2-debuginfo / libpmi0 / etc");
}
