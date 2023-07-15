#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:3343-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105353);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2015-3193", "CVE-2016-0701", "CVE-2017-3732", "CVE-2017-3736", "CVE-2017-3737", "CVE-2017-3738");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : openssl (SUSE-SU-2017:3343-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openssl fixes the following issues :

  - OpenSSL Security Advisory [07 Dec 2017]

  - CVE-2017-3737: OpenSSL 1.0.2 (starting from version
    1.0.2b) introduced an \'error state\' mechanism. The
    intent was that if a fatal error occurred during a
    handshake then OpenSSL would move into the error state
    and would immediately fail if you attempted to continue
    the handshake. This works as designed for the explicit
    handshake functions (SSL_do_handshake(), SSL_accept()
    and SSL_connect()), however due to a bug it does not
    work correctly if SSL_read() or SSL_write() is called
    directly. In that scenario, if the handshake fails then
    a fatal error will be returned in the initial function
    call. If SSL_read()/SSL_write() is subsequently called
    by the application for the same SSL object then it will
    succeed and the data is passed without being
    decrypted/encrypted directly from the SSL/TLS record
    layer. In order to exploit this issue an application bug
    would have to be present that resulted in a call to
    SSL_read()/SSL_write() being issued after having already
    received a fatal error. OpenSSL version 1.0.2b-1.0.2m
    are affected. Fixed in OpenSSL 1.0.2n. OpenSSL 1.1.0 is
    not affected. (bsc#1071905)

  - CVE-2017-3738: There is an overflow bug in the AVX2
    Montgomery multiplication procedure used in
    exponentiation with 1024-bit moduli. No EC algorithms
    are affected. Analysis suggests that attacks against RSA
    and DSA as a result of this defect would be very
    difficult to perform and are not believed likely.
    Attacks against DH1024 are considered just feasible,
    because most of the work necessary to deduce information
    about a private key may be performed offline. The amount
    of resources required for such an attack would be
    significant. However, for an attack on TLS to be
    meaningful, the server would have to share the DH1024
    private key among multiple clients, which is no longer
    an option since CVE-2016-0701. This only affects
    processors that support the AVX2 but not ADX extensions
    like Intel Haswell (4th generation). Note: The impact
    from this issue is similar to CVE-2017-3736,
    CVE-2017-3732 and CVE-2015-3193. (bsc#1071906)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1071905"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1071906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3737/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3738/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20173343-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6ecfb0bf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2017-2097=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2017-2097=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-2097=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2017-2097=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-2097=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2017-2097=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-2097=1

SUSE Container as a Service Platform ALL:zypper in -t patch
SUSE-CAASP-ALL-2017-2097=1

OpenStack Cloud Magnum Orchestration 7:zypper in -t patch
SUSE-OpenStack-Cloud-Magnum-Orchestration-7-2017-2097=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"libopenssl-devel-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libopenssl1_0_0-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libopenssl1_0_0-debuginfo-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libopenssl1_0_0-hmac-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"openssl-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"openssl-debuginfo-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"openssl-debugsource-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libopenssl1_0_0-32bit-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libopenssl1_0_0-hmac-32bit-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libopenssl-devel-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libopenssl1_0_0-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libopenssl1_0_0-debuginfo-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libopenssl1_0_0-hmac-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openssl-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openssl-debuginfo-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openssl-debugsource-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libopenssl1_0_0-32bit-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libopenssl1_0_0-hmac-32bit-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libopenssl-devel-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libopenssl1_0_0-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libopenssl1_0_0-32bit-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"openssl-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"openssl-debuginfo-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"openssl-debugsource-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libopenssl-devel-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libopenssl1_0_0-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libopenssl1_0_0-32bit-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"openssl-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"openssl-debuginfo-1.0.2j-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"openssl-debugsource-1.0.2j-60.20.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl");
}
