#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-742.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101135);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-2581", "CVE-2017-2586", "CVE-2017-2587");

  script_name(english:"openSUSE Security Update : netpbm (openSUSE-2017-742)");
  script_summary(english:"Check for the openSUSE-2017-742 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for netpbm fixes the following issues :

Security bugs :

  - CVE-2017-2586: A NULL pointer dereference in
    stringToUint function could lead to a denial of service
    (abort) problem when processing malformed images.
    [bsc#1024292]

  - CVE-2017-2581: A out-of-bounds write in writeRasterPbm()
    could be used by attackers to crash the decoder or
    potentially execute code. [bsc#1024287]

  - CVE-2017-2587: A insufficient size check of memory
    allocation in createCanvas() function could be used for
    a denial of service attack (memory exhaustion)
    [bsc#1024294]

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024287"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024294"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected netpbm packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetpbm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetpbm11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetpbm11-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetpbm11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetpbm11-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:netpbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:netpbm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:netpbm-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libnetpbm-devel-10.66.3-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libnetpbm11-10.66.3-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libnetpbm11-debuginfo-10.66.3-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"netpbm-10.66.3-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"netpbm-debuginfo-10.66.3-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"netpbm-debugsource-10.66.3-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libnetpbm11-32bit-10.66.3-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libnetpbm11-debuginfo-32bit-10.66.3-8.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libnetpbm-devel / libnetpbm11 / libnetpbm11-32bit / etc");
}
