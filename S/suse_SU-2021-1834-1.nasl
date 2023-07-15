#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:1834-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(150200);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/07");

  script_cve_id("CVE-2021-3509", "CVE-2021-3524", "CVE-2021-3531");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : ceph (SUSE-SU-2021:1834-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ceph fixes the following issues :

Update to 15.2.12-83-g528da226523 :

(CVE-2021-3509) fix cookie injection issue (bsc#1186021)

(CVE-2021-3531) RGWSwiftWebsiteHandler::is_web_dir checks empty
subdir_name (bsc#1186020)

(CVE-2021-3524) sanitize \r in s3
CORSConfiguration&acirc;&#128;&#153;s ExposeHeader (bsc#1185619)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1185619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1186020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1186021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-3509/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-3524/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-3531/"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20211834-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?378fb269"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE MicroOS 5.0 :

zypper in -t patch SUSE-SUSE-MicroOS-5.0-2021-1834=1

SUSE Linux Enterprise Module for Basesystem 15-SP3 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP3-2021-1834=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2021-1834=1

SUSE Enterprise Storage 7 :

zypper in -t patch SUSE-Storage-7-2021-1834=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3524");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcephfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcephfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcephfs2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librados-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librados-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librados2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libradospp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librbd1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librgw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librgw2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-ceph-argparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-cephfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rados-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rgw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rados-objclass-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rbd-nbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rbd-nbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2/3", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"3", reference:"ceph-common-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"ceph-common-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"ceph-debugsource-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libcephfs-devel-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libcephfs2-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libcephfs2-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"librados-devel-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"librados-devel-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"librados2-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"librados2-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libradospp-devel-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"librbd-devel-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"librbd1-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"librbd1-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"librgw-devel-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"librgw2-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"librgw2-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"python3-ceph-argparse-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"python3-ceph-common-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"python3-cephfs-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"python3-cephfs-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"python3-rados-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"python3-rados-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"python3-rbd-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"python3-rbd-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"python3-rgw-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"python3-rgw-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"rados-objclass-devel-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"rbd-nbd-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"rbd-nbd-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"ceph-common-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"ceph-common-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"ceph-debugsource-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libcephfs-devel-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libcephfs2-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libcephfs2-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"librados-devel-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"librados-devel-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"librados2-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"librados2-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libradospp-devel-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"librbd-devel-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"librbd1-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"librbd1-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"librgw-devel-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"librgw2-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"librgw2-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-ceph-argparse-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-ceph-common-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-cephfs-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-cephfs-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-rados-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-rados-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-rbd-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-rbd-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-rgw-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-rgw-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"rados-objclass-devel-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"rbd-nbd-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"rbd-nbd-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"ceph-common-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"ceph-common-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"ceph-debugsource-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libcephfs-devel-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libcephfs2-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libcephfs2-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"librados-devel-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"librados-devel-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"librados2-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"librados2-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libradospp-devel-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"librbd-devel-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"librbd1-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"librbd1-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"librgw-devel-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"librgw2-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"librgw2-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"python3-ceph-argparse-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"python3-ceph-common-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"python3-cephfs-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"python3-cephfs-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"python3-rados-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"python3-rados-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"python3-rbd-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"python3-rbd-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"python3-rgw-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"python3-rgw-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"rados-objclass-devel-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"rbd-nbd-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"rbd-nbd-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"ceph-common-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"ceph-common-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"ceph-debugsource-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libcephfs-devel-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libcephfs2-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libcephfs2-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"librados-devel-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"librados-devel-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"librados2-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"librados2-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libradospp-devel-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"librbd-devel-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"librbd1-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"librbd1-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"librgw-devel-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"librgw2-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"librgw2-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-ceph-argparse-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-ceph-common-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-cephfs-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-cephfs-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-rados-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-rados-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-rbd-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-rbd-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-rgw-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-rgw-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"rados-objclass-devel-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"rbd-nbd-15.2.12.83+g528da226523-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"rbd-nbd-debuginfo-15.2.12.83+g528da226523-3.25.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ceph");
}
