#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-889.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102249);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-10970", "CVE-2017-11163", "CVE-2017-11691", "CVE-2017-12065");

  script_name(english:"openSUSE Security Update : cacti / cacti-spine (openSUSE-2017-889)");
  script_summary(english:"Check for the openSUSE-2017-889 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for cacti, cacti-spine fixes the following issues :

  - CVE-2017-12065: Possible code execution via avgnan,
    outlier-start, or outlier-end parameter (bsc#1051633)

  - CVE-2017-11691: XSS in auth_profile.php allows remote
    attackers to inject arbitrary JS via specially crafted
    HTTP Referer headers (bsc#1050950)

  - CVE-2017-10970: XSS Issue in link.php bsc#1047512

  - CVE-2017-11163: XSS Issue in lib/html_form.php
    bsc#1048102

In addition, cacti and cacti-spine were updated to the current stable
release 1.1.16, containing all upstream improvements and bugfixes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051633"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cacti / cacti-spine packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti-spine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti-spine-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti-spine-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"cacti-1.1.16-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"cacti-spine-1.1.16-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"cacti-spine-debuginfo-1.1.16-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"cacti-spine-debugsource-1.1.16-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cacti-1.1.16-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cacti-spine-1.1.16-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cacti-spine-debuginfo-1.1.16-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cacti-spine-debugsource-1.1.16-10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cacti-spine / cacti-spine-debuginfo / cacti-spine-debugsource / etc");
}
