#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1397.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125210);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-15134", "CVE-2017-15135", "CVE-2018-10850", "CVE-2018-10935", "CVE-2018-14624");

  script_name(english:"openSUSE Security Update : 389-ds (openSUSE-2019-1397)");
  script_summary(english:"Check for the openSUSE-2019-1397 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for 389-ds fixes the following issues :

The following security vulnerabilities were addressed :

  - CVE-2018-10850: Fixed a race condition on reference
    counter that would lead to a denial of service using
    persistent search (bsc#1096368)

  - CVE-2017-15134: Fixed a remote denial of service via
    search filters in slapi_filter_sprintf in slapd/util.c
    (bsc#1076530)

  - CVE-2017-15135: Fixed authentication bypass due to lack
    of size check in slapi_ct_memcmp function in ch_malloc.c
    (bsc#1076530)

  - CVE-2018-10935: Fixed an issue that allowed users to
    cause a crash via ldapsearch with server side sorts
    (bsc#1105606)

  - CVE-2018-14624: The lock controlling the error log was
    not correctly used when re-opening the log file in
    log__error_emergency(), allowing an attacker to send a
    flood of modifications to a very large DN, which could
    have caused slapd to crash (bsc#1106699).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076530"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096368"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106699"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 389-ds packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15135");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:389-ds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:389-ds-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:389-ds-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:389-ds-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:389-ds-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:389-ds-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/16");
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

if ( rpm_check(release:"SUSE15.0", reference:"389-ds-1.4.0.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"389-ds-debuginfo-1.4.0.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"389-ds-debugsource-1.4.0.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"389-ds-devel-1.4.0.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"389-ds-snmp-1.4.0.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"389-ds-snmp-debuginfo-1.4.0.3-lp150.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds / 389-ds-debuginfo / 389-ds-debugsource / 389-ds-devel / etc");
}
