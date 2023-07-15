#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-168.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106863);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-2177", "CVE-2016-2178", "CVE-2016-2179", "CVE-2016-2180", "CVE-2016-2181", "CVE-2016-2182", "CVE-2016-2183", "CVE-2016-6302", "CVE-2016-6303", "CVE-2016-6304", "CVE-2016-6306", "CVE-2016-7052", "CVE-2016-7055", "CVE-2016-7056", "CVE-2017-3731", "CVE-2017-3732");

  script_name(english:"openSUSE Security Update : openssl-steam (openSUSE-2018-168)");
  script_summary(english:"Check for the openSUSE-2018-168 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openssl-steam fixes the following issues :

  - Merged changes from upstream openssl (Factory rev 137)
    into this fork for Steam.

Updated to openssl 1.0.2k :

  - CVE-2016-7055: Montgomery multiplication may produce
    incorrect results (boo#1009528)

  - CVE-2016-7056: ECSDA P-256 timing attack key recovery
    (boo#1019334)

  - CVE-2017-3731: Truncated packet could crash via OOB read
    (boo#1022085)

  - CVE-2017-3732: BN_mod_exp may produce incorrect results
    on x86_64 (boo#1022086)

Update to openssl-1.0.2j :

  - CVE-2016-7052: Missing CRL sanity check (boo#1001148)

OpenSSL Security Advisory [22 Sep 2016] (boo#999665)

  - Severity: High

  - CVE-2016-6304: OCSP Status Request extension unbounded
    memory growth (boo#999666)

  - Severity: Low

  - CVE-2016-2177: Pointer arithmetic undefined behaviour
    (boo#982575)

  - CVE-2016-2178: Constant time flag not preserved in DSA
    signing (boo#983249)

  - CVE-2016-2179: DTLS buffered message DoS (boo#994844)

  - CVE-2016-2180: OOB read in TS_OBJ_print_bio()
    (boo#990419)

  - CVE-2016-2181: DTLS replay protection DoS (boo#994749)

  - CVE-2016-2182: OOB write in BN_bn2dec() (boo#993819)

  - CVE-2016-2183: Birthday attack against 64-bit block
    ciphers (SWEET32) (boo#995359)

  - CVE-2016-6302: Malformed SHA512 ticket DoS (boo#995324)

  - CVE-2016-6303: OOB write in MDC2_Update() (boo#995377)

  - CVE-2016-6306: Certificate message OOB reads
    (boo#999668)

ALso fixed :

  - fixed a crash in print_notice (boo#998190)

  - fix X509_CERT_FILE path (boo#1022271) and rename

  - resume reading from /dev/urandom when interrupted by a
    signal (boo#995075)

  - fix problems with locking in FIPS mode (boo#992120)

  - duplicates: boo#991877, boo#991193, boo#990392,
    boo#990428 and boo#990207

  - drop openssl-fips_RSA_compute_d_with_lcm.patch
    (upstream) (boo#984323)

  - don't check for /etc/system-fips (boo#982268)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1001148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022085"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022271"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982268"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982575"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=992120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=993819"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=995075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=995324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=995359"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=995377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=998190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=999665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=999666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=999668"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl-steam packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-steam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-steam-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-steam-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-steam-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-steam-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/16");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"libopenssl1_0_0-steam-1.0.2k-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libopenssl1_0_0-steam-debuginfo-1.0.2k-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openssl-steam-debugsource-1.0.2k-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libopenssl1_0_0-steam-32bit-1.0.2k-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libopenssl1_0_0-steam-debuginfo-32bit-1.0.2k-4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libopenssl1_0_0-steam / libopenssl1_0_0-steam-32bit / etc");
}
