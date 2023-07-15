#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2318-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(120077);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/18");

  script_cve_id("CVE-2018-10858", "CVE-2018-10918", "CVE-2018-10919", "CVE-2018-1139", "CVE-2018-1140");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : samba (SUSE-SU-2018:2318-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for samba fixes the following issues: The following
security vulnerabilities were fixed :

  - CVE-2018-1139: Disable NTLMv1 auth if smb.conf doesn't
    allow it; (bsc#1095048)

  - CVE-2018-1140: ldbsearch '(distinguishedName=abc)' and
    DNS query with escapes crashes; (bsc#1095056)

  - CVE-2018-10919: Confidential attribute disclosure via
    substring search; (bsc#1095057)

  - CVE-2018-10858: smbc_urlencode helper function is a
    subject to buffer overflow; (bsc#1103411)

  - CVE-2018-10918: Fix NULL ptr dereference in DsCrackNames
    on a user without a SPN; (bsc#1103414)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1095048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1095056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1095057"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1103411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1103414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10858/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10918/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10919/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-1139/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-1140/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182318-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d1de0a9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2018-1555=1

SUSE Linux Enterprise High Availability 15:zypper in -t patch
SUSE-SLE-Product-HA-15-2018-1555=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-samr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-samr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-samr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", reference:"libdcerpc-binding0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libdcerpc-binding0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libdcerpc-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libdcerpc-samr-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libdcerpc-samr0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libdcerpc-samr0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libdcerpc0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libdcerpc0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-krb5pac-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-krb5pac0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-krb5pac0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-nbt-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-nbt0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-nbt0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-standard-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-standard0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-standard0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libnetapi-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libnetapi0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libnetapi0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-credentials-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-credentials0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-credentials0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-errors-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-errors0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-errors0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-hostconfig-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-hostconfig0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-hostconfig0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-passdb-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-passdb0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-passdb0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-policy-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-policy0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-util-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-util0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-util0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamdb-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamdb0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamdb0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbclient-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbclient0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbclient0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbconf-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbconf0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbconf0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbldap-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbldap2-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbldap2-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtevent-util-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtevent-util0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtevent-util0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libwbclient-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libwbclient0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libwbclient0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-client-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-client-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-core-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-debugsource-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-libs-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-libs-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-winbind-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-winbind-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libdcerpc-binding0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libdcerpc-binding0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libdcerpc-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libdcerpc-samr-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libdcerpc-samr0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libdcerpc-samr0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libdcerpc0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libdcerpc0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-krb5pac-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-krb5pac0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-krb5pac0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-nbt-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-nbt0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-nbt0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-standard-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-standard0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-standard0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libnetapi-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libnetapi0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libnetapi0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-credentials-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-credentials0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-credentials0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-errors-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-errors0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-errors0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-hostconfig-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-hostconfig0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-hostconfig0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-passdb-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-passdb0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-passdb0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-policy-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-policy0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-util-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-util0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-util0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamdb-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamdb0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamdb0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbclient-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbclient0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbclient0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbconf-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbconf0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbconf0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbldap-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbldap2-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbldap2-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtevent-util-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtevent-util0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtevent-util0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libwbclient-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libwbclient0-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libwbclient0-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-client-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-client-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-core-devel-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-debugsource-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-libs-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-libs-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-winbind-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-winbind-debuginfo-4.7.8+git.86.94b6d10f7dd-4.15.1")) flag++;


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
