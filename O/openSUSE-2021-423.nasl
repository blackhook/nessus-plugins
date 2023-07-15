#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-423.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(147850);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/09");

  script_cve_id("CVE-2021-3393");

  script_name(english:"openSUSE Security Update : postgresql12 (openSUSE-2021-423)");
  script_summary(english:"Check for the openSUSE-2021-423 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for postgresql12 fixes the following issues :

Upgrade to version 12.6 :

  - Reindexing might be needed after applying this update.

  - CVE-2021-3393, bsc#1182040: Fix information leakage in
    constraint-violation error messages.

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179765"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182040"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected postgresql12 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3393");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-llvmjit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-llvmjit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-server-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql12-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/17");
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

if ( rpm_check(release:"SUSE15.2", reference:"libecpg6-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libecpg6-debuginfo-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libpq5-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libpq5-debuginfo-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-contrib-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-contrib-debuginfo-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-debuginfo-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-debugsource-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-devel-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-devel-debuginfo-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-llvmjit-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-llvmjit-debuginfo-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-plperl-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-plperl-debuginfo-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-plpython-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-plpython-debuginfo-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-pltcl-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-pltcl-debuginfo-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-server-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-server-debuginfo-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-server-devel-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-server-devel-debuginfo-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"postgresql12-test-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libecpg6-32bit-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libecpg6-32bit-debuginfo-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libpq5-32bit-12.6-lp152.3.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libpq5-32bit-debuginfo-12.6-lp152.3.16.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libecpg6 / libecpg6-debuginfo / libpq5 / libpq5-debuginfo / etc");
}
