#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:2721-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(143864);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/23");

  script_cve_id("CVE-2020-1472");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2020/09/21");
  script_xref(name:"CISA-NCAS", value:"AA22-011A");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");
  script_xref(name:"CEA-ID", value:"CEA-2020-0101");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0008");
  script_xref(name:"CEA-ID", value:"CEA-2020-0121");
  script_xref(name:"CEA-ID", value:"CEA-2023-0016");

  script_name(english:"SUSE SLES12 Security Update : samba (SUSE-SU-2020:2721-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for samba fixes the following issues :

ZeroLogon: An elevation of privilege was possible with some
configurations when an attacker established a vulnerable Netlogon
secure channel connection to a domain controller, using the Netlogon
Remote Protocol (MS-NRPC) (CVE-2020-1472, bsc#1176579).

Fixed an issue where multiple home folders were created(bsc#1174316,
bso#13369).

Fixed an issue where the net command was unable to negotiate SMB2
(bsc#1174120);

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174316");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1176579");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-1472/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20202721-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c4b90b2");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 9 :

zypper in -t patch SUSE-OpenStack-Cloud-Crowbar-9-2020-2721=1

SUSE OpenStack Cloud Crowbar 8 :

zypper in -t patch SUSE-OpenStack-Cloud-Crowbar-8-2020-2721=1

SUSE OpenStack Cloud 9 :

zypper in -t patch SUSE-OpenStack-Cloud-9-2020-2721=1

SUSE OpenStack Cloud 8 :

zypper in -t patch SUSE-OpenStack-Cloud-8-2020-2721=1

SUSE Linux Enterprise Server for SAP 12-SP4 :

zypper in -t patch SUSE-SLE-SAP-12-SP4-2020-2721=1

SUSE Linux Enterprise Server for SAP 12-SP3 :

zypper in -t patch SUSE-SLE-SAP-12-SP3-2020-2721=1

SUSE Linux Enterprise Server 12-SP4-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP4-LTSS-2020-2721=1

SUSE Linux Enterprise Server 12-SP3-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-2020-2721=1

SUSE Linux Enterprise Server 12-SP3-BCL :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-BCL-2020-2721=1

SUSE Linux Enterprise High Availability 12-SP4 :

zypper in -t patch SUSE-SLE-HA-12-SP4-2020-2721=1

SUSE Linux Enterprise High Availability 12-SP3 :

zypper in -t patch SUSE-SLE-HA-12-SP3-2020-2721=1

SUSE Enterprise Storage 5 :

zypper in -t patch SUSE-Storage-5-2020-2721=1

HPE Helion Openstack 8 :

zypper in -t patch HPE-Helion-OpenStack-8-2020-2721=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1472");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"libdcerpc-binding0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libdcerpc-binding0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libdcerpc-binding0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libdcerpc-binding0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libdcerpc0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libdcerpc0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libdcerpc0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libdcerpc0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libndr-krb5pac0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libndr-krb5pac0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libndr-krb5pac0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libndr-krb5pac0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libndr-nbt0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libndr-nbt0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libndr-nbt0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libndr-nbt0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libndr-standard0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libndr-standard0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libndr-standard0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libndr-standard0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libndr0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libndr0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libndr0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libndr0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libnetapi0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libnetapi0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libnetapi0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libnetapi0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsamba-credentials0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsamba-credentials0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsamba-credentials0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsamba-credentials0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsamba-errors0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsamba-errors0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsamba-errors0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsamba-errors0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsamba-hostconfig0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsamba-hostconfig0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsamba-hostconfig0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsamba-hostconfig0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsamba-passdb0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsamba-passdb0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsamba-passdb0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsamba-passdb0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsamba-util0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsamba-util0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsamba-util0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsamba-util0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsamdb0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsamdb0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsamdb0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsamdb0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsmbclient0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsmbclient0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsmbclient0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsmbclient0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsmbconf0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsmbconf0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsmbconf0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsmbconf0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsmbldap0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsmbldap0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsmbldap0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsmbldap0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libtevent-util0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libtevent-util0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libtevent-util0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libtevent-util0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libwbclient0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libwbclient0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libwbclient0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libwbclient0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"samba-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"samba-client-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"samba-client-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"samba-client-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"samba-client-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"samba-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"samba-debugsource-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"samba-libs-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"samba-libs-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"samba-libs-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"samba-libs-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"samba-winbind-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"samba-winbind-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"samba-winbind-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"samba-winbind-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libdcerpc-binding0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libdcerpc-binding0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libdcerpc-binding0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libdcerpc-binding0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libdcerpc0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libdcerpc0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libdcerpc0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libdcerpc0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-krb5pac0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-krb5pac0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-krb5pac0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-krb5pac0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-nbt0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-nbt0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-nbt0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-nbt0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-standard0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-standard0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-standard0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-standard0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libnetapi0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libnetapi0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libnetapi0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libnetapi0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-credentials0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-credentials0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-credentials0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-credentials0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-errors0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-errors0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-errors0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-errors0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-hostconfig0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-hostconfig0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-hostconfig0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-hostconfig0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-passdb0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-passdb0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-passdb0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-passdb0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-util0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-util0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-util0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-util0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamdb0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamdb0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamdb0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamdb0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbclient0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbclient0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbclient0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbclient0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbconf0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbconf0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbconf0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbconf0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbldap0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbldap0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbldap0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbldap0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libtevent-util0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libtevent-util0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libtevent-util0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libtevent-util0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwbclient0-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwbclient0-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwbclient0-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwbclient0-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-client-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-client-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-client-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-client-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-debugsource-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-libs-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-libs-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-libs-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-libs-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-winbind-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-winbind-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-winbind-debuginfo-32bit-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-winbind-debuginfo-4.6.16+git.237.40a3f495f75-3.55.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
