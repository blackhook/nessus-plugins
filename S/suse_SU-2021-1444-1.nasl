#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:1444-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(149185);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2020-27840", "CVE-2021-20254", "CVE-2021-20277");
  script_xref(name:"IAVA", value:"2021-A-0208-S");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : samba (SUSE-SU-2021:1444-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for samba fixes the following issues :

CVE-2021-20277: Fixed an out of bounds read in ldb_handler_fold
(bsc#1183574).

CVE-2021-20254: Fixed a buffer overrun in sids_to_unixids()
(bsc#1184677).

CVE-2020-27840: Fixed an unauthenticated remote heap corruption via
bad DNs (bsc#1183572).

Avoid free'ing our own pointer in memcache when memcache_trim attempts
to reduce cache size (bsc#1179156).

s3-libads: use dns name to open a ldap session (bsc#1184310).

Adjust smbcacls '--propagate-inheritance' feature to align with
upstream (bsc#1178469).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178469");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179156");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184310");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184677");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27840/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20254/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20277/");
  # https://www.suse.com/support/update/announcement/2021/suse-su-20211444-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ccc0b3f6");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Python2 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Python2-15-SP2-2021-1444=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2021-1444=1

SUSE Linux Enterprise High Availability 15-SP2 :

zypper in -t patch SUSE-SLE-Product-HA-15-SP2-2021-1444=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20254");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-samr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-samr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-samr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy-python3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy0-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy0-python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-ad-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-ad-dc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-ceph-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-dsdb-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-dsdb-modules-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libdcerpc0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libdcerpc0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libndr-nbt0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libndr-nbt0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libndr-standard0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libndr-standard0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libndr0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libndr0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libnetapi0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libnetapi0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsamba-credentials0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsamba-credentials0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsamba-errors0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsamba-errors0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsamba-passdb0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsamba-passdb0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsamba-util0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsamba-util0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsamdb0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsamdb0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsmbconf0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsmbconf0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsmbldap2-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsmbldap2-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libtevent-util0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libtevent-util0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libwbclient0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libwbclient0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"samba-ceph-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"samba-ceph-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"samba-libs-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"samba-libs-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"samba-winbind-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"samba-winbind-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libdcerpc-binding0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libdcerpc-binding0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libdcerpc-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libdcerpc-samr-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libdcerpc-samr0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libdcerpc-samr0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libdcerpc0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libdcerpc0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libndr-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libndr-krb5pac-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libndr-krb5pac0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libndr-krb5pac0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libndr-nbt-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libndr-nbt0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libndr-nbt0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libndr-standard-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libndr-standard0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libndr-standard0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libndr0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libndr0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libnetapi-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libnetapi0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libnetapi0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-credentials-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-credentials0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-credentials0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-errors-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-errors0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-errors0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-hostconfig-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-hostconfig0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-hostconfig0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-passdb-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-passdb0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-passdb0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-policy-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-policy-python3-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-policy0-python3-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-policy0-python3-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-util-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-util0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-util0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamdb-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamdb0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamdb0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsmbclient-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsmbclient0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsmbclient0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsmbconf-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsmbconf0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsmbconf0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsmbldap-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsmbldap2-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsmbldap2-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libtevent-util-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libtevent-util0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libtevent-util0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libwbclient-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libwbclient0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libwbclient0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-ad-dc-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-ad-dc-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-client-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-client-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-core-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-debugsource-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-dsdb-modules-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-dsdb-modules-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-libs-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-libs-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-libs-python3-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-libs-python3-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-python3-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-python3-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-winbind-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-winbind-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libdcerpc0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libdcerpc0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libndr-nbt0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libndr-nbt0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libndr-standard0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libndr-standard0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libndr0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libndr0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libnetapi0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libnetapi0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsamba-credentials0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsamba-credentials0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsamba-errors0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsamba-errors0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsamba-passdb0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsamba-passdb0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsamba-util0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsamba-util0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsamdb0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsamdb0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsmbconf0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsmbconf0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsmbldap2-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsmbldap2-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libtevent-util0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libtevent-util0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libwbclient0-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libwbclient0-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"samba-ceph-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"samba-ceph-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"samba-libs-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"samba-libs-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"samba-winbind-32bit-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"samba-winbind-32bit-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libdcerpc-binding0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libdcerpc-binding0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libdcerpc-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libdcerpc-samr-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libdcerpc-samr0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libdcerpc-samr0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libdcerpc0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libdcerpc0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libndr-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libndr-krb5pac-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libndr-krb5pac0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libndr-krb5pac0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libndr-nbt-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libndr-nbt0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libndr-nbt0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libndr-standard-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libndr-standard0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libndr-standard0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libndr0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libndr0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libnetapi-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libnetapi0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libnetapi0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-credentials-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-credentials0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-credentials0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-errors-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-errors0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-errors0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-hostconfig-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-hostconfig0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-hostconfig0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-passdb-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-passdb0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-passdb0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-policy-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-policy-python3-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-policy0-python3-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-policy0-python3-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-util-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-util0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-util0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamdb-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamdb0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamdb0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsmbclient-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsmbclient0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsmbclient0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsmbconf-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsmbconf0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsmbconf0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsmbldap-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsmbldap2-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsmbldap2-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libtevent-util-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libtevent-util0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libtevent-util0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libwbclient-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libwbclient0-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libwbclient0-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-ad-dc-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-ad-dc-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-client-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-client-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-core-devel-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-debugsource-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-dsdb-modules-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-dsdb-modules-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-libs-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-libs-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-libs-python3-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-libs-python3-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-python3-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-python3-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-winbind-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-winbind-debuginfo-4.11.14+git.247.8c858f7ee14-4.19.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
