#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0663-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(146944);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-17437",
    "CVE-2020-13987",
    "CVE-2020-13988",
    "CVE-2020-17437",
    "CVE-2020-17438"
  );
  script_xref(name:"CEA-ID", value:"CEA-2020-0139");

  script_name(english:"SUSE SLES12 Security Update : open-iscsi (SUSE-SU-2021:0663-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for open-iscsi fixes the following issues :

Fixes for CVE-2019-17437, CVE-2020-17438, CVE-2020-13987 and
CVE-2020-13988 (bsc#1179908) :

check for TCP urgent pointer past end of frame

check for u8 overflow when processing TCP options

check for header length underflow during checksum calculation

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179908");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-13987/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-13988/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-17437/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-17438/");
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210663-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a53f165d");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 9 :

zypper in -t patch SUSE-OpenStack-Cloud-Crowbar-9-2021-663=1

SUSE OpenStack Cloud 9 :

zypper in -t patch SUSE-OpenStack-Cloud-9-2021-663=1

SUSE Linux Enterprise Server for SAP 12-SP4 :

zypper in -t patch SUSE-SLE-SAP-12-SP4-2021-663=1

SUSE Linux Enterprise Server 12-SP5 :

zypper in -t patch SUSE-SLE-SERVER-12-SP5-2021-663=1

SUSE Linux Enterprise Server 12-SP4-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP4-LTSS-2021-663=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:iscsiuio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:iscsiuio-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopeniscsiusr0_2_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopeniscsiusr0_2_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:open-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:open-iscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:open-iscsi-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP4/5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"iscsiuio-0.7.8.2-12.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"iscsiuio-debuginfo-0.7.8.2-12.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libopeniscsiusr0_2_0-2.0.876-12.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libopeniscsiusr0_2_0-debuginfo-2.0.876-12.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"open-iscsi-2.0.876-12.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"open-iscsi-debuginfo-2.0.876-12.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"open-iscsi-debugsource-2.0.876-12.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"iscsiuio-0.7.8.2-12.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"iscsiuio-debuginfo-0.7.8.2-12.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libopeniscsiusr0_2_0-2.0.876-12.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libopeniscsiusr0_2_0-debuginfo-2.0.876-12.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"open-iscsi-2.0.876-12.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"open-iscsi-debuginfo-2.0.876-12.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"open-iscsi-debugsource-2.0.876-12.27.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "open-iscsi");
}
