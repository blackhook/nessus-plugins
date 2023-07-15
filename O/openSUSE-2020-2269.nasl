#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2269.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(145353);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-1971");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"openSUSE Security Update : openssl-1_0_0 (openSUSE-2020-2269)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for openssl-1_0_0 fixes the following issues :

  - CVE-2020-1971: Fixed a NULL pointer dereference in
    EDIPARTYNAME (bsc#1179491).

  - Initialized dh->nid to NID_undef in DH_new_method()
    (bsc#1177673).

  - Fixed a test failure in apache_ssl in fips mode
    (bsc#1177793).

  - Renamed BN_get_rfc3526_prime_* functions back to
    get_rfc3526_prime_* (bsc#1177575).

  - Restored private key check in EC_KEY_check_key
    (bsc#1177479).

  - Added shared secret KAT to FIPS DH selftest
    (bsc#1176029).

  - Included ECDH/DH Requirements from SP800-56Arev3
    (bsc#1176029).

  - Used SHA-2 in the RSA pairwise consistency check
    (bsc#1155346)

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176029");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177793");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179491");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssl-1_0_0 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl-1_0_0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl-1_0_0-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-hmac-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-steam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-steam-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-steam-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-steam-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-1_0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-1_0_0-cavs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-1_0_0-cavs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-1_0_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-1_0_0-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"libopenssl-1_0_0-devel-1.0.2p-lp151.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libopenssl10-1.0.2p-lp151.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libopenssl10-debuginfo-1.0.2p-lp151.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libopenssl1_0_0-1.0.2p-lp151.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libopenssl1_0_0-debuginfo-1.0.2p-lp151.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libopenssl1_0_0-hmac-1.0.2p-lp151.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libopenssl1_0_0-steam-1.0.2p-lp151.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libopenssl1_0_0-steam-debuginfo-1.0.2p-lp151.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openssl-1_0_0-1.0.2p-lp151.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openssl-1_0_0-cavs-1.0.2p-lp151.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openssl-1_0_0-cavs-debuginfo-1.0.2p-lp151.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openssl-1_0_0-debuginfo-1.0.2p-lp151.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openssl-1_0_0-debugsource-1.0.2p-lp151.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libopenssl-1_0_0-devel-32bit-1.0.2p-lp151.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libopenssl1_0_0-32bit-1.0.2p-lp151.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libopenssl1_0_0-32bit-debuginfo-1.0.2p-lp151.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libopenssl1_0_0-hmac-32bit-1.0.2p-lp151.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libopenssl1_0_0-steam-32bit-1.0.2p-lp151.5.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libopenssl1_0_0-steam-32bit-debuginfo-1.0.2p-lp151.5.20.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libopenssl-1_0_0-devel / libopenssl10 / libopenssl10-debuginfo / etc");
}
