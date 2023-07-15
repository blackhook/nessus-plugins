#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0948-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(135387);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2020-11501");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : gmp, gnutls, libnettle (SUSE-SU-2020:0948-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for gmp, gnutls, libnettle fixes the following issues :

Security issue fixed :

CVE-2020-11501: Fixed zero random value in DTLS client hello
(bsc#1168345)

FIPS related bugfixes: FIPS: Install checksums for binary integrity
verification which are required when running in FIPS mode
(bsc#1152692, jsc#SLE-9518)

FIPS: Fixed a cfb8 decryption issue, no longer truncate output IV if
input is shorter than block size. (bsc#1166881)

FIPS: Added Diffie Hellman public key verification test. (bsc#1155327)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1152692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1155327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1166881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1168345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-11501/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200948-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?36d1dd4b"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15:zypper in -t patch
SUSE-SLE-Product-SLES_SAP-15-2020-948=1

SUSE Linux Enterprise Server 15-LTSS:zypper in -t patch
SUSE-SLE-Product-SLES-15-2020-948=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP2:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP2-2020-948=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-948=1

SUSE Linux Enterprise Module for Development Tools 15-SP2:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-SP2-2020-948=1

SUSE Linux Enterprise Module for Development Tools 15-SP1:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-SP1-2020-948=1

SUSE Linux Enterprise Module for Basesystem 15-SP2:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP2-2020-948=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2020-948=1

SUSE Linux Enterprise High Performance Computing 15-LTSS:zypper in -t
patch SUSE-SLE-Product-HPC-15-2020-948=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS:zypper in -t
patch SUSE-SLE-Product-HPC-15-2020-948=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11501");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gmp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gnutls-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gnutls-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gnutls-guile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gnutls-guile-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgmp10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgmp10-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgmp10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgmpxx4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgmpxx4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgmpxx4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgnutls30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgnutls30-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgnutls30-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgnutls30-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgnutlsxx-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgnutlsxx28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgnutlsxx28-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhogweed4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhogweed4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhogweed4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnettle-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnettle-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnettle6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnettle6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnettle6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nettle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nettle-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"gmp-devel-32bit-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgmp10-32bit-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgmp10-32bit-debuginfo-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgmpxx4-32bit-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgmpxx4-32bit-debuginfo-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgnutls-devel-32bit-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgnutls30-32bit-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgnutls30-32bit-debuginfo-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgnutls30-hmac-32bit-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libhogweed4-32bit-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libhogweed4-32bit-debuginfo-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libnettle-devel-32bit-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libnettle6-32bit-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libnettle6-32bit-debuginfo-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gmp-debugsource-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gmp-devel-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gnutls-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gnutls-debuginfo-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gnutls-debugsource-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gnutls-guile-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gnutls-guile-debuginfo-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgmp10-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgmp10-debuginfo-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgmpxx4-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgmpxx4-debuginfo-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgnutls-devel-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgnutls30-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgnutls30-debuginfo-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgnutls30-hmac-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgnutlsxx-devel-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgnutlsxx28-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgnutlsxx28-debuginfo-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libhogweed4-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libhogweed4-debuginfo-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libnettle-debugsource-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libnettle-devel-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libnettle6-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libnettle6-debuginfo-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"nettle-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"nettle-debuginfo-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gmp-debugsource-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gmp-devel-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gnutls-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gnutls-debuginfo-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gnutls-debugsource-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgmp10-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgmp10-debuginfo-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgmpxx4-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgmpxx4-debuginfo-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgnutls-devel-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgnutls30-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgnutls30-debuginfo-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgnutls30-hmac-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgnutlsxx-devel-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgnutlsxx28-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgnutlsxx28-debuginfo-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libhogweed4-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libhogweed4-debuginfo-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libnettle-debugsource-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libnettle-devel-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libnettle6-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libnettle6-debuginfo-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"gmp-devel-32bit-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libgmp10-32bit-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libgmp10-32bit-debuginfo-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libgmpxx4-32bit-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libgmpxx4-32bit-debuginfo-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libgnutls-devel-32bit-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libgnutls30-32bit-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libgnutls30-32bit-debuginfo-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libhogweed4-32bit-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libhogweed4-32bit-debuginfo-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libnettle-devel-32bit-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libnettle6-32bit-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libnettle6-32bit-debuginfo-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gmp-debugsource-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gmp-devel-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gnutls-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gnutls-debuginfo-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gnutls-debugsource-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gnutls-guile-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"gnutls-guile-debuginfo-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgmp10-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgmp10-debuginfo-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgmpxx4-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgmpxx4-debuginfo-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgnutls-devel-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgnutls30-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgnutls30-debuginfo-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgnutlsxx-devel-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgnutlsxx28-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libgnutlsxx28-debuginfo-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libhogweed4-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libhogweed4-debuginfo-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libnettle-debugsource-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libnettle-devel-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libnettle6-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libnettle6-debuginfo-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"nettle-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"nettle-debuginfo-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"gmp-devel-32bit-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgmp10-32bit-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgmp10-32bit-debuginfo-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgmpxx4-32bit-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgmpxx4-32bit-debuginfo-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgnutls-devel-32bit-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgnutls30-32bit-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgnutls30-32bit-debuginfo-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgnutls30-hmac-32bit-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libhogweed4-32bit-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libhogweed4-32bit-debuginfo-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libnettle-devel-32bit-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libnettle6-32bit-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libnettle6-32bit-debuginfo-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gmp-debugsource-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gmp-devel-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gnutls-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gnutls-debuginfo-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gnutls-debugsource-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gnutls-guile-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gnutls-guile-debuginfo-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgmp10-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgmp10-debuginfo-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgmpxx4-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgmpxx4-debuginfo-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgnutls-devel-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgnutls30-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgnutls30-debuginfo-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgnutls30-hmac-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgnutlsxx-devel-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgnutlsxx28-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgnutlsxx28-debuginfo-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libhogweed4-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libhogweed4-debuginfo-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libnettle-debugsource-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libnettle-devel-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libnettle6-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libnettle6-debuginfo-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"nettle-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"nettle-debuginfo-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"gmp-devel-32bit-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libgmp10-32bit-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libgmp10-32bit-debuginfo-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libgmpxx4-32bit-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libgmpxx4-32bit-debuginfo-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libgnutls-devel-32bit-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libgnutls30-32bit-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libgnutls30-32bit-debuginfo-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libhogweed4-32bit-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libhogweed4-32bit-debuginfo-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libnettle-devel-32bit-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libnettle6-32bit-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libnettle6-32bit-debuginfo-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gmp-debugsource-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gmp-devel-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gnutls-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gnutls-debuginfo-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gnutls-debugsource-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gnutls-guile-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"gnutls-guile-debuginfo-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgmp10-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgmp10-debuginfo-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgmpxx4-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgmpxx4-debuginfo-6.1.2-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgnutls-devel-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgnutls30-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgnutls30-debuginfo-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgnutlsxx-devel-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgnutlsxx28-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libgnutlsxx28-debuginfo-3.6.7-6.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libhogweed4-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libhogweed4-debuginfo-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libnettle-debugsource-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libnettle-devel-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libnettle6-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libnettle6-debuginfo-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"nettle-3.4.1-4.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"nettle-debuginfo-3.4.1-4.12.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gmp / gnutls / libnettle");
}
