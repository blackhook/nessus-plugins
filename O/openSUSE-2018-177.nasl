#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-177.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106895);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2017-16227",
    "CVE-2018-5378",
    "CVE-2018-5379",
    "CVE-2018-5380",
    "CVE-2018-5381"
  );
  script_xref(name:"CEA-ID", value:"CEA-2019-0227");

  script_name(english:"openSUSE Security Update : quagga (openSUSE-2018-177)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for quagga fixes the following issues :

  - CVE-2017-16227: Fixed bgpd DoS via specially crafted BGP
    UPDATE messages (boo#1065641)

  - CVE-2018-5378: Fixed bgpd bounds check issue via
    attribute length (Quagga-2018-0543,boo#1079798)

  - CVE-2018-5379: Fixed bgpd double free when processing
    UPDATE message (Quagga-2018-1114,boo#1079799)

  - CVE-2018-5380: Fixed bgpd code-to-string conversion
    tables overrun (Quagga-2018-1550,boo#1079800)

  - CVE-2018-5381: Fixed bgpd infinite loop on certain
    invalid OPEN messages (Quagga-2018-1975,boo#1079801)");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079800");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079801");
  script_set_attribute(attribute:"solution", value:
"Update the affected quagga packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfpm_pb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfpm_pb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libospf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libospf0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libospfapiclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libospfapiclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libquagga_pb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libquagga_pb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzebra1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzebra1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quagga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quagga-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quagga-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quagga-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 Tenable Network Security, Inc.");

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

if ( rpm_check(release:"SUSE42.3", reference:"libfpm_pb0-1.1.1-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libfpm_pb0-debuginfo-1.1.1-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libospf0-1.1.1-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libospf0-debuginfo-1.1.1-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libospfapiclient0-1.1.1-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libospfapiclient0-debuginfo-1.1.1-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libquagga_pb0-1.1.1-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libquagga_pb0-debuginfo-1.1.1-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libzebra1-1.1.1-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libzebra1-debuginfo-1.1.1-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"quagga-1.1.1-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"quagga-debuginfo-1.1.1-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"quagga-debugsource-1.1.1-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"quagga-devel-1.1.1-18.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libfpm_pb0 / libfpm_pb0-debuginfo / libospf0 / libospf0-debuginfo / etc");
}
