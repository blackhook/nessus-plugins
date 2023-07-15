#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1510.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125757);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-6891", "CVE-2018-1000654");

  script_name(english:"openSUSE Security Update : libtasn1 (openSUSE-2019-1510)");
  script_summary(english:"Check for the openSUSE-2019-1510 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libtasn1 fixes the following issues :

Security issues fixed :

  - CVE-2018-1000654: Fixed a denial of service in the asn1
    parser (bsc#1105435).

  - CVE-2017-6891: Fixed a stack overflow in
    asn1_find_node() (bsc#1040621).

This update was imported from the SUSE:SLE-12-SP3:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105435"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtasn1 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6891");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtasn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtasn1-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtasn1-6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtasn1-6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtasn1-6-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtasn1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtasn1-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtasn1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtasn1-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/07");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"libtasn1-4.9-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libtasn1-6-4.9-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libtasn1-6-debuginfo-4.9-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libtasn1-debuginfo-4.9-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libtasn1-debugsource-4.9-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libtasn1-devel-4.9-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libtasn1-6-32bit-4.9-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libtasn1-6-debuginfo-32bit-4.9-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libtasn1-devel-32bit-4.9-6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtasn1 / libtasn1-6-32bit / libtasn1-6 / etc");
}
