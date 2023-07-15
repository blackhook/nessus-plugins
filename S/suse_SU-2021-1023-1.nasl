#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:1023-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(148365);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/23");

  script_cve_id(
    "CVE-2020-28368",
    "CVE-2021-3308",
    "CVE-2021-20257",
    "CVE-2021-28687"
  );

  script_name(english:"SUSE SLES12 Security Update : xen (SUSE-SU-2021:1023-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for xen fixes the following issues :

CVE-2021-3308: VUL-0: xen: IRQ vector leak on x86 (bsc#1181254,
XSA-360)

CVE-2021-28687: VUL-0: xen: HVM soft-reset crashes toolstack
(bsc#1183072, XSA-368)

CVE-2021-20257: VUL-0: xen: infinite loop issue in the e1000 NIC
emulator (bsc#1182846)

CVE-2020-28368: VUL-0: xen: Intel RAPL sidechannel attack aka PLATYPUS
attack aka (bsc#1178591, XSA-351)

L3: conring size for XEN HV's with huge memory to small. Inital Xen
logs cut (bsc#1177204)

Kdump of HVM fails, soft-reset not handled by libxl (bsc#1179148)

OpenQA job causes libvirtd to dump core when running kdump inside
domain (bsc#1181989)

Allow restart of xenwatchdogd, enable tuning of keep-alive interval
and timeout options via XENWATCHDOGD_ARGS= (bsc#1178736)

The receiving side did detect holes in a to-be-allocated superpage,
but allocated a superpage anyway. This resulted to over-allocation
(bsc#1177112)

The receiving side may punch holes incorrectly into optimistically
allocated superpages. Also reduce overhead in bitmap handling
(bsc#1177112)

Upstream bug fixes (bsc#1027519)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1027519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1177112");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1177204");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178736");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181254");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1182846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183072");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-28368/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20257/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28687/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3308/");
  # https://www.suse.com/support/update/announcement/2021/suse-su-20211023-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e01e1452");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP5 :

zypper in -t patch SUSE-SLE-SDK-12-SP5-2021-1023=1

SUSE Linux Enterprise Server 12-SP5 :

zypper in -t patch SUSE-SLE-SERVER-12-SP5-2021-1023=1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28368");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU-debuginfo");
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
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"5", cpu:"x86_64", reference:"xen-4.12.4_09-3.39.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", cpu:"x86_64", reference:"xen-debugsource-4.12.4_09-3.39.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", cpu:"x86_64", reference:"xen-doc-html-4.12.4_09-3.39.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", cpu:"x86_64", reference:"xen-libs-32bit-4.12.4_09-3.39.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", cpu:"x86_64", reference:"xen-libs-4.12.4_09-3.39.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.12.4_09-3.39.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", cpu:"x86_64", reference:"xen-libs-debuginfo-4.12.4_09-3.39.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", cpu:"x86_64", reference:"xen-tools-4.12.4_09-3.39.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", cpu:"x86_64", reference:"xen-tools-debuginfo-4.12.4_09-3.39.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", cpu:"x86_64", reference:"xen-tools-domU-4.12.4_09-3.39.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", cpu:"x86_64", reference:"xen-tools-domU-debuginfo-4.12.4_09-3.39.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
