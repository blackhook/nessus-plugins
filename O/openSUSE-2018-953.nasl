#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-953.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(112267);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-12434", "CVE-2018-8970");

  script_name(english:"openSUSE Security Update : libressl (openSUSE-2018-953)");
  script_summary(english:"Check for the openSUSE-2018-953 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libressl to version 2.8.0 fixes the following issues :

Security issues fixed :

  - CVE-2018-12434: Avoid a timing side-channel leak when
    generating DSA and ECDSA signatures. (boo#1097779)

  - Reject excessively large primes in DH key generation.

  - CVE-2018-8970: Fixed a bug in int_x509_param_set_hosts,
    calling strlen() if name length provided is 0 to match
    the OpenSSL behaviour. (boo#1086778)

  - Fixed an out-of-bounds read and crash in DES-fcrypt
    (boo#1065363)

You can find a detailed list of changes
[here](https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.8.0-rel
notes.txt)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097779"
  );
  # https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.8.0-relnotes.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5af67e40"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libressl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto43");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto43-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto43-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto43-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl45");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl45-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl45-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl45-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls17-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls17-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls17-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/04");
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

if ( rpm_check(release:"SUSE42.3", reference:"libcrypto43-2.8.0-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libcrypto43-debuginfo-2.8.0-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libressl-2.8.0-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libressl-debuginfo-2.8.0-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libressl-debugsource-2.8.0-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libressl-devel-2.8.0-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libssl45-2.8.0-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libssl45-debuginfo-2.8.0-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libtls17-2.8.0-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libtls17-debuginfo-2.8.0-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libcrypto43-32bit-2.8.0-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libcrypto43-debuginfo-32bit-2.8.0-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libressl-devel-32bit-2.8.0-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libssl45-32bit-2.8.0-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libssl45-debuginfo-32bit-2.8.0-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libtls17-32bit-2.8.0-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libtls17-debuginfo-32bit-2.8.0-11.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcrypto43 / libcrypto43-32bit / libcrypto43-debuginfo / etc");
}
