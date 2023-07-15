#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:3551-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(143867);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2019-3855",
    "CVE-2019-3856",
    "CVE-2019-3857",
    "CVE-2019-3858",
    "CVE-2019-3859",
    "CVE-2019-3860",
    "CVE-2019-3861",
    "CVE-2019-3862",
    "CVE-2019-3863",
    "CVE-2019-17498"
  );

  script_name(english:"SUSE SLED15 / SLES15 Security Update : libssh2_org (SUSE-SU-2020:3551-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for libssh2_org fixes the following issues :

Version update to 1.9.0: [bsc#1178083, jsc#SLE-16922] Enhancements and
bugfixes :

  - adds ECDSA keys and host key support when using OpenSSL

  - adds ED25519 key and host key support when using OpenSSL
    1.1.1

  - adds OpenSSH style key file reading

  - adds AES CTR mode support when using WinCNG

  - adds PEM passphrase protected file support for Libgcrypt
    and WinCNG

  - adds SHA256 hostkey fingerprint

  - adds libssh2_agent_get_identity_path() and
    libssh2_agent_set_identity_path()

  - adds explicit zeroing of sensitive data in memory

  - adds additional bounds checks to network buffer reads

  - adds the ability to use the server default permissions
    when creating sftp directories

  - adds support for building with OpenSSL no engine flag

  - adds support for building with LibreSSL

  - increased sftp packet size to 256k

  - fixed oversized packet handling in sftp

  - fixed building with OpenSSL 1.1

  - fixed a possible crash if sftp stat gets an unexpected
    response

  - fixed incorrect parsing of the KEX preference string
    value

  - fixed conditional RSA and AES-CTR support

  - fixed a small memory leak during the key exchange
    process

  - fixed a possible memory leak of the ssh banner string

  - fixed various small memory leaks in the backends

  - fixed possible out of bounds read when parsing public
    keys from the server

  - fixed possible out of bounds read when parsing invalid
    PEM files

  - no longer null terminates the scp remote exec command

  - now handle errors when diffie hellman key pair
    generation fails

  - improved building instructions

  - improved unit tests

Version update to 1.8.2: [bsc#1130103] Bug fixes :

  - Fixed the misapplied userauth patch that broke 1.8.1

  - moved the MAX size declarations from the public header

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1130103");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178083");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17498/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-3855/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-3856/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-3857/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-3858/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-3859/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-3860/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-3861/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-3862/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-3863/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20203551-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb71abe2");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2020-3551=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2020-3551=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2020-3551=1

SUSE Linux Enterprise Module for Basesystem 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP1-2020-3551=1

SUSE Linux Enterprise High Performance Computing 15-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-3551=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-3551=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3855");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-3862");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libssh2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libssh2-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libssh2-1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libssh2-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libssh2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libssh2_org-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1/2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1/2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libssh2-1-32bit-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libssh2-1-32bit-debuginfo-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libssh2-1-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libssh2-1-debuginfo-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libssh2-devel-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libssh2_org-debugsource-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libssh2-1-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libssh2-1-debuginfo-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libssh2-devel-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libssh2_org-debugsource-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libssh2-1-32bit-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libssh2-1-32bit-debuginfo-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libssh2-1-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libssh2-1-debuginfo-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libssh2-devel-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libssh2_org-debugsource-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libssh2-1-32bit-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libssh2-1-32bit-debuginfo-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libssh2-1-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libssh2-1-debuginfo-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libssh2-devel-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libssh2_org-debugsource-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libssh2-1-32bit-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libssh2-1-32bit-debuginfo-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libssh2-1-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libssh2-1-debuginfo-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libssh2-devel-1.9.0-4.13.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libssh2_org-debugsource-1.9.0-4.13.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libssh2_org");
}
