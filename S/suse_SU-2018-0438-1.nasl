#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0438-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(106834);
  script_version("3.7");
  script_cvs_date("Date: 2019/09/10 13:51:46");

  script_cve_id("CVE-2017-15595", "CVE-2017-17563", "CVE-2017-17564", "CVE-2017-17565", "CVE-2017-17566", "CVE-2017-18030", "CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754", "CVE-2018-5683");
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : xen (SUSE-SU-2018:0438-1) (Meltdown) (Spectre)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xen fixes several issues. These security issues were
fixed :

  - CVE-2017-5753, CVE-2017-5715, CVE-2017-5754: Prevent
    information leaks via side effects of speculative
    execution, aka 'Spectre' and 'Meltdown' attacks
    (bsc#1074562, bsc#1068032)

  - CVE-2017-15595: x86 PV guest OS users were able to cause
    a DoS (unbounded recursion, stack consumption, and
    hypervisor crash) or possibly gain privileges via
    crafted page-table stacking (bsc#1061081)

  - CVE-2017-17566: Prevent PV guest OS users to cause a
    denial of service (host OS crash) or gain host OS
    privileges in shadow mode by mapping a certain auxiliary
    page (bsc#1070158).

  - CVE-2017-17563: Prevent guest OS users to cause a denial
    of service (host OS crash) or gain host OS privileges by
    leveraging an incorrect mask for reference-count
    overflow checking in shadow mode (bsc#1070159).

  - CVE-2017-17564: Prevent guest OS users to cause a denial
    of service (host OS crash) or gain host OS privileges by
    leveraging incorrect error handling for reference
    counting in shadow mode (bsc#1070160).

  - CVE-2017-17565: Prevent PV guest OS users to cause a
    denial of service (host OS crash) if shadow mode and
    log-dirty mode are in place, because of an incorrect
    assertion related to M2P (bsc#1070163).

  - CVE-2018-5683: The vga_draw_text function allowed local
    OS guest privileged users to cause a denial of service
    (out-of-bounds read and QEMU process crash) by
    leveraging improper memory address validation
    (bsc#1076116).

  - CVE-2017-18030: The cirrus_invalidate_region function
    allowed local OS guest privileged users to cause a
    denial of service (out-of-bounds array access and QEMU
    process crash) via vectors related to negative pitch
    (bsc#1076180).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1027519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1035442"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1051729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1067317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1068032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1070158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1070159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1070160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1070163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074562"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1076116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1076180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15595/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17563/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17564/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17565/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17566/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-18030/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5715/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5753/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5754/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5683/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180438-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa241230"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-302=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-302=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-302=1

SUSE CaaS Platform ALL:zypper in -t patch SUSE-CAASP-ALL-2018-302=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/15");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"xen-4.9.1_08-3.26.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"xen-debugsource-4.9.1_08-3.26.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"xen-doc-html-4.9.1_08-3.26.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"xen-libs-32bit-4.9.1_08-3.26.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"xen-libs-4.9.1_08-3.26.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.9.1_08-3.26.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"xen-libs-debuginfo-4.9.1_08-3.26.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"xen-tools-4.9.1_08-3.26.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"xen-tools-debuginfo-4.9.1_08-3.26.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"xen-tools-domU-4.9.1_08-3.26.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"xen-tools-domU-debuginfo-4.9.1_08-3.26.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"xen-4.9.1_08-3.26.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"xen-debugsource-4.9.1_08-3.26.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"xen-libs-32bit-4.9.1_08-3.26.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"xen-libs-4.9.1_08-3.26.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.9.1_08-3.26.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"xen-libs-debuginfo-4.9.1_08-3.26.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
