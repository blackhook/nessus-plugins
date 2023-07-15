#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-102.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106431);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-11423", "CVE-2017-12374", "CVE-2017-12375", "CVE-2017-12376", "CVE-2017-12377", "CVE-2017-12378", "CVE-2017-12379", "CVE-2017-12380", "CVE-2017-6418", "CVE-2017-6419", "CVE-2017-6420");

  script_name(english:"openSUSE Security Update : clamav (openSUSE-2018-102)");
  script_summary(english:"Check for the openSUSE-2018-102 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for clamav fixes the following issues :

  - Update to security release 0.99.3 (bsc#1077732)

  - CVE-2017-12376 (ClamAV Buffer Overflow in handle_pdfname
    Vulnerability)

  - CVE-2017-12377 (ClamAV Mew Packet Heap Overflow
    Vulnerability)

  - CVE-2017-12379 (ClamAV Buffer Overflow in
    messageAddArgument Vulnerability)

  - these vulnerabilities could have allowed an
    unauthenticated, remote attacker to cause a denial of
    service (DoS) condition or potentially execute arbitrary
    code on an affected device.

  - CVE-2017-12374 (ClamAV use-after-free Vulnerabilities)

  - CVE-2017-12375 (ClamAV Buffer Overflow Vulnerability)

  - CVE-2017-12378 (ClamAV Buffer Over Read Vulnerability)

  - CVE-2017-12380 (ClamAV Null Dereference Vulnerability)

  - these vulnerabilities could have allowed an
    unauthenticated, remote attacker to cause a denial of
    service (DoS) condition on an affected device.

  - CVE-2017-6420 (bsc#1052448)

  - this vulnerability could have allowed remote attackers
    to cause a denial of service (use-after-free) via a
    crafted PE file with WWPack compression.

  - CVE-2017-6419 (bsc#1052449)

  - ClamAV could have allowed remote attackers to cause a
    denial of service (heap-based buffer overflow and
    application crash) or possibly have unspecified other
    impact via a crafted CHM file.

  - CVE-2017-11423 (bsc#1049423)

  - ClamAV could have allowed remote attackers to cause a
    denial of service (stack-based buffer over-read and
    application crash) via a crafted CAB file.

  - CVE-2017-6418 (bsc#1052466)

  - ClamAV could have allowed remote attackers to cause a
    denial of service (out-of-bounds read) via a crafted
    e-mail message.

  - update upstream keys in the keyring

  - provide and obsolete clamav-nodb to trigger it's removal
    in Leap bsc#1040662

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077732"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected clamav packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clamav-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clamav-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"clamav-0.99.3-20.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"clamav-debuginfo-0.99.3-20.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"clamav-debugsource-0.99.3-20.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clamav / clamav-debuginfo / clamav-debugsource");
}
