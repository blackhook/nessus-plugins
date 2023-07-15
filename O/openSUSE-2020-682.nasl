#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-682.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(136880);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/28");

  script_cve_id("CVE-2020-11758", "CVE-2020-11760", "CVE-2020-11761", "CVE-2020-11762", "CVE-2020-11763", "CVE-2020-11764", "CVE-2020-11765");

  script_name(english:"openSUSE Security Update : openexr (openSUSE-2020-682)");
  script_summary(english:"Check for the openSUSE-2020-682 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for openexr provides the following fix :

Security issues fixed :

  - CVE-2020-11765: Fixed an off-by-one error in use of the
    ImfXdr.h read function by
    DwaCompressor:Classifier:Classifier (bsc#1169575).

  - CVE-2020-11764: Fixed an out-of-bounds write in
    copyIntoFrameBuffer in ImfMisc.cpp (bsc#1169574).

  - CVE-2020-11763: Fixed an out-of-bounds read and write,
    as demonstrated by ImfTileOffsets.cpp (bsc#1169576).

  - CVE-2020-11762: Fixed an out-of-bounds read and write in
    DwaCompressor:uncompress in ImfDwaCompressor.cpp when
    handling the UNKNOWN compression case (bsc#1169549).

  - CVE-2020-11761: Fixed an out-of-bounds read during
    Huffman uncompression, as demonstrated by
    FastHufDecoder:refill in ImfFastHuf.cpp (bsc#1169578).

  - CVE-2020-11760: Fixed an out-of-bounds read during RLE
    uncompression in rleUncompress in ImfRle.cpp
    (bsc#1169580).

  - CVE-2020-11758: Fixed an out-of-bounds read in
    ImfOptimizedPixelReading.h (bsc#1169573).

Non-security issue fixed :

  - Enable tests when building the package on x86_64.
    (bsc#1146648)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146648"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169574"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169575"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169580"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected openexr packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"libIlmImf-2_2-23-2.2.1-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libIlmImf-2_2-23-debuginfo-2.2.1-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libIlmImfUtil-2_2-23-2.2.1-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libIlmImfUtil-2_2-23-debuginfo-2.2.1-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openexr-2.2.1-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openexr-debuginfo-2.2.1-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openexr-debugsource-2.2.1-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openexr-devel-2.2.1-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libIlmImf-2_2-23-32bit-2.2.1-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libIlmImf-2_2-23-32bit-debuginfo-2.2.1-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libIlmImfUtil-2_2-23-32bit-2.2.1-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libIlmImfUtil-2_2-23-32bit-debuginfo-2.2.1-lp151.4.9.1") ) flag++;

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
