#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1385.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118881);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-16391", "CVE-2018-16392", "CVE-2018-16393", "CVE-2018-16418", "CVE-2018-16419", "CVE-2018-16420", "CVE-2018-16421", "CVE-2018-16422", "CVE-2018-16423", "CVE-2018-16424", "CVE-2018-16425", "CVE-2018-16426", "CVE-2018-16427");

  script_name(english:"openSUSE Security Update : opensc (openSUSE-2018-1385)");
  script_summary(english:"Check for the openSUSE-2018-1385 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for opensc fixes the following security issues :

  - CVE-2018-16391: Fixed a denial of service when handling
    responses from a Muscle Card (bsc#1106998)

  - CVE-2018-16392: Fixed a denial of service when handling
    responses from a TCOS Card (bsc#1106999)

  - CVE-2018-16393: Fixed buffer overflows when handling
    responses from Gemsafe V1 Smartcards (bsc#1108318)

  - CVE-2018-16418: Fixed buffer overflow when handling
    string concatenation in util_acl_to_str (bsc#1107039)

  - CVE-2018-16419: Fixed several buffer overflows when
    handling responses from a Cryptoflex card (bsc#1107107)

  - CVE-2018-16420: Fixed buffer overflows when handling
    responses from an ePass 2003 Card (bsc#1107097)

  - CVE-2018-16421: Fixed buffer overflows when handling
    responses from a CAC Card (bsc#1107049)

  - CVE-2018-16422: Fixed single byte buffer overflow when
    handling responses from an esteid Card (bsc#1107038)

  - CVE-2018-16423: Fixed double free when handling
    responses from a smartcard (bsc#1107037)

  - CVE-2018-16424: Fixed double free when handling
    responses in read_file (bsc#1107036)

  - CVE-2018-16425: Fixed double free when handling
    responses from an HSM Card (bsc#1107035)

  - CVE-2018-16426: Fixed endless recursion when handling
    responses from an IAS-ECC card (bsc#1107034)

  - CVE-2018-16427: Fixed out of bounds reads when handling
    responses in OpenSC (bsc#1107033)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106999"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107033"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107036"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107037"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107039"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108318"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected opensc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opensc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opensc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opensc-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opensc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opensc-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/10");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"opensc-0.18.0-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"opensc-debuginfo-0.18.0-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"opensc-debugsource-0.18.0-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"opensc-32bit-0.18.0-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"opensc-32bit-debuginfo-0.18.0-lp150.2.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "opensc / opensc-debuginfo / opensc-debugsource / opensc-32bit / etc");
}
