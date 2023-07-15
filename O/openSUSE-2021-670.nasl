#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-670.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149558);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2021-3477",
    "CVE-2021-3479",
    "CVE-2021-20296",
    "CVE-2021-23215",
    "CVE-2021-26260"
  );

  script_name(english:"openSUSE Security Update : openexr (openSUSE-2021-670)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for openexr fixes the following issues :

  - CVE-2021-23215: Fixed an integer-overflow in
    Imf_2_5:DwaCompressor:initializeBuffers (bsc#1185216).

  - CVE-2021-26260: Fixed an Integer-overflow in
    Imf_2_5:DwaCompressor:initializeBuffers (bsc#1185217).

  - CVE-2021-20296: Fixed a NULL pointer dereference in
    Imf_2_5:hufUncompress (bsc#1184355).

  - CVE-2021-3477: Fixed a Heap-buffer-overflow in
    Imf_2_5::DeepTiledInputFile::readPixelSampleCounts
    (bsc#1184353).

  - CVE-2021-3479: Fixed an Out-of-memory caused by
    allocation of a very large buffer (bsc#1184354).

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184354");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184355");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185216");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185217");
  script_set_attribute(attribute:"solution", value:
"Update the affected openexr packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20296");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3479");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libIlmImf-2_2-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libIlmImf-2_2-23-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libIlmImf-2_2-23-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libIlmImf-2_2-23-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libIlmImfUtil-2_2-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libIlmImfUtil-2_2-23-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libIlmImfUtil-2_2-23-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libIlmImfUtil-2_2-23-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openexr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openexr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openexr-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openexr-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.2", reference:"libIlmImf-2_2-23-2.2.1-lp152.7.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libIlmImf-2_2-23-debuginfo-2.2.1-lp152.7.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libIlmImfUtil-2_2-23-2.2.1-lp152.7.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libIlmImfUtil-2_2-23-debuginfo-2.2.1-lp152.7.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openexr-2.2.1-lp152.7.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openexr-debuginfo-2.2.1-lp152.7.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openexr-debugsource-2.2.1-lp152.7.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openexr-devel-2.2.1-lp152.7.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libIlmImf-2_2-23-32bit-2.2.1-lp152.7.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libIlmImf-2_2-23-32bit-debuginfo-2.2.1-lp152.7.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libIlmImfUtil-2_2-23-32bit-2.2.1-lp152.7.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libIlmImfUtil-2_2-23-32bit-debuginfo-2.2.1-lp152.7.14.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libIlmImf-2_2-23 / libIlmImf-2_2-23-debuginfo / etc");
}
