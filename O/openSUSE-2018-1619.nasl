#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1619.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119949);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-5804", "CVE-2018-5805", "CVE-2018-5806", "CVE-2018-5808", "CVE-2018-5816");

  script_name(english:"openSUSE Security Update : libraw (openSUSE-2018-1619)");
  script_summary(english:"Check for the openSUSE-2018-1619 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libraw fixes the following issues :

The following security vulnerabilities were addressed :

  - CVE-2018-5804: Fixed a type confusion error within the
    identify function that could trigger a division by zero,
    leading to a denial of service (Dos). (boo#1097975)

  - CVE-2018-5805: Fixed a boundary error within the
    quicktake_100_load_raw function that could cause a
    stack-based buffer overflow and subsequently trigger a
    crash. (boo#1097973)

  - CVE-2018-5806: Fixed an error within the
    leaf_hdr_load_raw function that could trigger a NULL
    pointer deference, leading to a denial of service (DoS).
    (boo#1097974)

  - CVE-2018-5808: Fixed an error within the find_green
    function that could cause a stack-based buffer overflow
    and subsequently execute arbitrary code. (boo#1118894)

  - CVE-2018-5816: Fixed a type confusion error within the
    identify function that could trigger a division by zero,
    leading to a denial of service (DoS). (boo#1097975)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118894"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libraw packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5808");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libraw-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libraw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libraw-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libraw-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libraw-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libraw15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libraw15-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE42.3", reference:"libraw-debugsource-0.17.1-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libraw-devel-0.17.1-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libraw-devel-static-0.17.1-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libraw-tools-0.17.1-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libraw-tools-debuginfo-0.17.1-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libraw15-0.17.1-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libraw15-debuginfo-0.17.1-26.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libraw-debugsource / libraw-devel / libraw-devel-static / etc");
}
