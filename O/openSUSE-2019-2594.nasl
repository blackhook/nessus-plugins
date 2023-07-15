#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2594.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131537);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-10811", "CVE-2018-16151", "CVE-2018-16152", "CVE-2018-17540", "CVE-2018-5388");

  script_name(english:"openSUSE Security Update : strongswan (openSUSE-2019-2594)");
  script_summary(english:"Check for the openSUSE-2019-2594 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for strongswan fixes the following issues :

Security issues fixed :

  - CVE-2018-5388: Fixed a buffer underflow which may allow
    to a remote attacker with local user credentials to
    resource exhaustion and denial of service while reading
    from the socket (bsc#1094462).

  - CVE-2018-10811: Fixed a denial of service during the
    IKEv2 key derivation if the openssl plugin is used in
    FIPS mode and HMAC-MD5 is negotiated as PRF
    (bsc#1093536).

  - CVE-2018-16151,CVE-2018-16152: Fixed multiple flaws in
    the gmp plugin which might lead to authorization bypass
    (bsc#1107874).

  - CVE-2018-17540: Fixed an improper input validation in
    gmp plugin (bsc#1109845). 

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107874"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109845"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected strongswan packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16152");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-ipsec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-ipsec-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-libs0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-libs0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-nm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-nm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"strongswan-5.6.0-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"strongswan-debuginfo-5.6.0-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"strongswan-debugsource-5.6.0-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"strongswan-hmac-5.6.0-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"strongswan-ipsec-5.6.0-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"strongswan-ipsec-debuginfo-5.6.0-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"strongswan-libs0-5.6.0-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"strongswan-libs0-debuginfo-5.6.0-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"strongswan-mysql-5.6.0-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"strongswan-mysql-debuginfo-5.6.0-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"strongswan-nm-5.6.0-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"strongswan-nm-debuginfo-5.6.0-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"strongswan-sqlite-5.6.0-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"strongswan-sqlite-debuginfo-5.6.0-lp150.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "strongswan / strongswan-debuginfo / strongswan-debugsource / etc");
}
