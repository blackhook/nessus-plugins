#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-536.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(148436);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/14");

  script_cve_id("CVE-2021-3474", "CVE-2021-3475", "CVE-2021-3476");

  script_name(english:"openSUSE Security Update : openexr (openSUSE-2021-536)");
  script_summary(english:"Check for the openSUSE-2021-536 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for openexr fixes the following issues :

  - CVE-2021-3474: Undefined-shift in
    Imf_2_5::FastHufDecoder::FastHufDecoder (bsc#1184174)

  - CVE-2021-3475: Integer-overflow in
    Imf_2_5::calculateNumTiles (bsc#1184173)

  - CVE-2021-3476: Undefined-shift in Imf_2_5::unpack14
    (bsc#1184172)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184174"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected openexr packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/12");
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

if ( rpm_check(release:"SUSE15.2", reference:"libIlmImf-2_2-23-2.2.1-lp152.7.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libIlmImf-2_2-23-debuginfo-2.2.1-lp152.7.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libIlmImfUtil-2_2-23-2.2.1-lp152.7.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libIlmImfUtil-2_2-23-debuginfo-2.2.1-lp152.7.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openexr-2.2.1-lp152.7.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openexr-debuginfo-2.2.1-lp152.7.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openexr-debugsource-2.2.1-lp152.7.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openexr-devel-2.2.1-lp152.7.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libIlmImf-2_2-23-32bit-2.2.1-lp152.7.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libIlmImf-2_2-23-32bit-debuginfo-2.2.1-lp152.7.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libIlmImfUtil-2_2-23-32bit-2.2.1-lp152.7.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libIlmImfUtil-2_2-23-32bit-debuginfo-2.2.1-lp152.7.11.1") ) flag++;

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
