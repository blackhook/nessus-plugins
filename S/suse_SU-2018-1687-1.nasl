#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:1687-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(110531);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-1057");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : samba (SUSE-SU-2018:1687-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Samba was updated to 4.6.14, fixing bugs and security issues: Version
update to 4.6.14 (bsc#1093664) :

  + vfs_ceph: add fake async pwrite/pread send/recv hooks;
    (bso#13425).

  + Fix memory leak in vfs_ceph; (bso#13424).

  + winbind: avoid using fstrcpy(dcname,...) in
    _dual_init_connection; (bso#13294).

  + s3:smb2_server: correctly maintain request counters for
    compound requests; (bso#13215).

  + s3: smbd: Unix extensions attempts to change wrong field
    in fchown call; (bso#13375).

  + s3:smbd: map nterror on smb2_flush errorpath;
    (bso#13338).

  + vfs_glusterfs: Fix the wrong pointer being sent in
    glfs_fsync_async; (bso#13297).

  + s3: smbd: Fix possible directory fd leak if the
    underlying OS doesn't support fdopendir(); (bso#13270).

  + s3: ldap: Ensure the ADS_STRUCT pointer doesn't get
    freed on error, we don't own it here; (bso#13244).

  + s3:libsmb: allow -U'\\administrator' to work;
    (bso#13206).

  + CVE-2018-1057: s4:dsdb: fix unprivileged password
    changes; (bso#13272); (bsc#1081024).

  + s3:smbd: Do not crash if we fail to init the session
    table; (bso#13315).

  + libsmb: Use smb2 tcon if conn_protocol >= SMB2_02;
    (bso#13310).

  + smbXcli: Add 'force_channel_sequence'; (bso#13215).

  + smbd: Fix channel sequence number checks for
    long-running requests; (bso#13215).

  + s3:smb2_server: allow logoff, close, unlock, cancel and
    echo on expired sessions; (bso#13197).

  + s3:smbd: return the correct error for cancelled SMB2
    notifies on expired sessions; (bso#13197).

  + samba: Only use async signal-safe functions in signal
    handler; (bso#13240).

  + subnet: Avoid a segfault when renaming subnet objects;
    (bso#13031).

  - Fix vfs_ceph with 'aio read size' or 'aio write size' >
    0; (bsc#1093664).

  + vfs_ceph: add fake async pwrite/pread send/recv hooks;
    (bso#13425).

  + Fix memory leak in vfs_ceph; (bso#13424).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1081024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1093664"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-1057/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20181687-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5fce8919"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-1132=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-1132=1

SUSE Linux Enterprise High Availability 12-SP3:zypper in -t patch
SUSE-SLE-HA-12-SP3-2018-1132=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-1132=1

SUSE Enterprise Storage 5:zypper in -t patch
SUSE-Storage-5-2018-1132=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"libdcerpc-binding0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libdcerpc-binding0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libdcerpc-binding0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libdcerpc-binding0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libdcerpc0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libdcerpc0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libdcerpc0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libdcerpc0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-krb5pac0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-krb5pac0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-krb5pac0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-krb5pac0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-nbt0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-nbt0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-nbt0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-nbt0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-standard0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-standard0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-standard0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-standard0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libnetapi0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libnetapi0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libnetapi0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libnetapi0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-credentials0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-credentials0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-credentials0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-credentials0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-errors0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-errors0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-errors0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-errors0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-hostconfig0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-hostconfig0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-hostconfig0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-hostconfig0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-passdb0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-passdb0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-passdb0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-passdb0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-util0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-util0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-util0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-util0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamdb0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamdb0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamdb0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamdb0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbclient0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbclient0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbclient0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbclient0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbconf0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbconf0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbconf0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbconf0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbldap0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbldap0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbldap0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbldap0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libtevent-util0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libtevent-util0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libtevent-util0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libtevent-util0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwbclient0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwbclient0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwbclient0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwbclient0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-client-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-client-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-client-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-client-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-debugsource-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-libs-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-libs-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-libs-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-libs-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-winbind-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-winbind-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-winbind-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-winbind-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libdcerpc-binding0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libdcerpc-binding0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libdcerpc-binding0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libdcerpc0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libdcerpc0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libdcerpc0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libdcerpc0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr-krb5pac0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr-krb5pac0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr-krb5pac0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr-nbt0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr-nbt0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr-nbt0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr-nbt0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr-standard0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr-standard0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr-standard0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr-standard0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libnetapi0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libnetapi0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libnetapi0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libnetapi0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-credentials0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-credentials0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-credentials0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-credentials0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-errors0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-errors0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-errors0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-errors0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-hostconfig0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-hostconfig0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-hostconfig0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-passdb0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-passdb0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-passdb0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-passdb0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-util0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-util0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-util0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-util0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamdb0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamdb0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamdb0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamdb0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsmbclient0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsmbclient0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsmbclient0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsmbconf0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsmbconf0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsmbconf0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsmbconf0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsmbldap0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsmbldap0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsmbldap0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsmbldap0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libtevent-util0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libtevent-util0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libtevent-util0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libtevent-util0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwbclient0-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwbclient0-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwbclient0-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-client-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-client-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-client-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-debugsource-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-libs-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-libs-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-libs-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-libs-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-winbind-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-winbind-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-4.6.14+git.150.1540e575faf-3.24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-winbind-debuginfo-4.6.14+git.150.1540e575faf-3.24.1")) flag++;


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
