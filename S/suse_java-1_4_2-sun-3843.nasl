#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update java-1_4_2-sun-3843.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(27276);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-0243", "CVE-2007-2788", "CVE-2007-2789");

  script_name(english:"openSUSE 10 Security Update : java-1_4_2-sun (java-1_4_2-sun-3843)");
  script_summary(english:"Check for the java-1_4_2-sun-3843 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Sun JAVA JDK 1.4.2 was upgraded to release 15 to fix various bugs,
including the following security bugs :

CVE-2007-2788 / CVE-2007-3004: Integer overflow in the embedded ICC
profile image parser in Sun Java Development Kit (JDK), allows remote
attackers to execute arbitrary code or cause a denial of service (JVM
crash) via a crafted JPEG or BMP file.

CVE-2007-2789 / CVE-2007-3005: The BMP image parser in Sun Java
Development Kit (JDK), on Unix/Linux systems, allows remote attackers
to trigger the opening of arbitrary local files via a crafted BMP
file, which causes a denial of service (system hang) in certain cases
such as /dev/tty, and has other unspecified impact.

CVE-2007-0243: Buffer overflow in Sun JDK and Java Runtime Environment
(JRE) allows applets to gain privileges via a GIF image with a block
with a 0 width field, which triggers memory corruption."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_4_2-sun packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_4_2-sun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_4_2-sun-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_4_2-sun-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_4_2-sun-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_4_2-sun-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_4_2-sun-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_4_2-sun-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686)$") audit(AUDIT_ARCH_NOT, "i586 / i686", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"java-1_4_2-sun-1.4.2.15-2.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"java-1_4_2-sun-alsa-1.4.2.15-2.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"java-1_4_2-sun-demo-1.4.2.15-2.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"java-1_4_2-sun-devel-1.4.2.15-2.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"java-1_4_2-sun-jdbc-1.4.2.15-2.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"java-1_4_2-sun-plugin-1.4.2.15-2.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"java-1_4_2-sun-src-1.4.2.15-2.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_4_2-sun-1.4.2_update15-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_4_2-sun-alsa-1.4.2_update15-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_4_2-sun-demo-1.4.2_update15-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_4_2-sun-devel-1.4.2_update15-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_4_2-sun-jdbc-1.4.2_update15-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_4_2-sun-plugin-1.4.2_update15-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_4_2-sun-src-1.4.2_update15-0.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_4_2-sun");
}
