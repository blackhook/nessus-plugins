#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:2822-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(143805);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2020-0543",
    "CVE-2020-14364",
    "CVE-2020-15565",
    "CVE-2020-15567",
    "CVE-2020-25595",
    "CVE-2020-25596",
    "CVE-2020-25597",
    "CVE-2020-25599",
    "CVE-2020-25600",
    "CVE-2020-25601",
    "CVE-2020-25603",
    "CVE-2020-25604"
  );

  script_name(english:"SUSE SLES12 Security Update : xen (SUSE-SU-2020:2822-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for xen fixes the following issues :

CVE-2020-25604: Fixed a race condition when migrating timers between
x86 HVM vCPU-s (bsc#1176343,XSA-336)

CVE-2020-25595: Fixed an issue where PCI passthrough code was reading
back hardware registers (bsc#1176344,XSA-337)

CVE-2020-25597: Fixed an issue where a valid event channels may not
turn invalid (bsc#1176346,XSA-338)

CVE-2020-25596: Fixed a potential denial of service in x86 pv guest
kernel via SYSENTER (bsc#1176345,XSA-339)

CVE-2020-25603: Fixed an issue due to missing barriers when
accessing/allocating an event channel (bsc#1176347,XSA-340)

CVE-2020-25600: Fixed out of bounds event channels available to 32-bit
x86 domains (bsc#1176348,XSA-342)

CVE-2020-25599: Fixed race conditions with evtchn_reset()
(bsc#1176349,XSA-343)

CVE-2020-25601: Fixed an issue due to lack of preemption in
evtchn_reset() / evtchn_destroy() (bsc#1176350,XSA-344)

CVE-2020-14364: Fixed an out-of-bounds read/write access while
processing usb packets (bsc#1175534).

CVE-2020-0543: Fixed a leak of Special Register Buffer Data Sampling
(SRBDS) aka 'CrossTalk' (bsc#1172205,XSA-320)

CVE-2020-15565: Fixed an issue cache write (bsc#1173378,XSA-321).

CVE-2020-15567: Fixed an issue with non-atomic modification of live
EPT PTE (bsc#1173380,XSA-328)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173378");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173380");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1175534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1176343");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1176344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1176345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1176346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1176347");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1176348");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1176349");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1176350");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-0543/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14364/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15565/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15567/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25595/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25596/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25597/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25599/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25600/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25601/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25603/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25604/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20202822-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7fc1d679");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 7 :

zypper in -t patch SUSE-OpenStack-Cloud-7-2020-2822=1

SUSE Linux Enterprise Server for SAP 12-SP2 :

zypper in -t patch SUSE-SLE-SAP-12-SP2-2020-2822=1

SUSE Linux Enterprise Server 12-SP2-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP2-2020-2822=1

SUSE Linux Enterprise Server 12-SP2-BCL :

zypper in -t patch SUSE-SLE-SERVER-12-SP2-BCL-2020-2822=1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25597");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-15565");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"xen-4.7.6_10-43.67.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"xen-debugsource-4.7.6_10-43.67.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"xen-doc-html-4.7.6_10-43.67.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"xen-libs-32bit-4.7.6_10-43.67.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"xen-libs-4.7.6_10-43.67.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.7.6_10-43.67.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"xen-libs-debuginfo-4.7.6_10-43.67.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"xen-tools-4.7.6_10-43.67.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"xen-tools-debuginfo-4.7.6_10-43.67.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"xen-tools-domU-4.7.6_10-43.67.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"xen-tools-domU-debuginfo-4.7.6_10-43.67.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
