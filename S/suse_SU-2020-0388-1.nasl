#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0388-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(133763);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/20");

  script_cve_id("CVE-2018-12207", "CVE-2018-19965", "CVE-2019-11135", "CVE-2019-12067", "CVE-2019-12068", "CVE-2019-12155", "CVE-2019-14378", "CVE-2019-15890", "CVE-2019-17340", "CVE-2019-17341", "CVE-2019-17342", "CVE-2019-17343", "CVE-2019-17344", "CVE-2019-17347", "CVE-2019-18420", "CVE-2019-18421", "CVE-2019-18424", "CVE-2019-18425", "CVE-2019-19577", "CVE-2019-19578", "CVE-2019-19579", "CVE-2019-19580", "CVE-2019-19581", "CVE-2019-19583", "CVE-2020-7211");

  script_name(english:"SUSE SLES12 Security Update : xen (SUSE-SU-2020:0388-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xen fixes the following issues :

CVE-2018-12207: Fixed a race condition where untrusted virtual
machines could have been using the Instruction Fetch Unit of the Intel
CPU to cause a Machine Exception during Page Size Change, causing the
CPU core to be non-functional (bsc#1155945 XSA-304).

CVE-2018-19965: Fixed a DoS from attempting to use INVPCID with a
non-canonical addresses (bsc#1115045 XSA-279).

CVE-2019-11135: Aborting an asynchronous TSX operation on Intel CPUs
with Transactional Memory support could be used to facilitate
side-channel information leaks out of microarchitectural buffers,
similar to the previously described 'Microarchitectural Data Sampling'
attack. (bsc#1152497 XSA-305).

CVE-2019-12067: Fixed a NULL pointer dereference in QEMU AHCI
(bsc#1145652).

CVE-2019-12068: Fixed an infinite loop while executing script
(bsc#1146874).

CVE-2019-12155: Fixed a NULL pointer dereference while releasing spice
resources (bsc#1135905).

CVE-2019-14378: Fixed a heap buffer overflow during packet reassembly
in slirp networking implementation (bsc#1143797).

CVE-2019-15890: Fixed a use-after-free during packet reassembly
(bsc#1149813).

CVE-2019-17340: Fixed grant table transfer issues on large hosts
(XSA-284 bsc#1126140).

CVE-2019-17341: Fixed a race with pass-through device hotplug (XSA-285
bsc#1126141).

CVE-2019-17342: Fixed steal_page violating page_struct access
discipline (XSA-287 bsc#1126192).

CVE-2019-17343: Fixed an inconsistent PV IOMMU discipline (XSA-288
bsc#1126195).

CVE-2019-17344: Fixed a missing preemption in x86 PV page table
unvalidation (XSA-290 bsc#1126196).

CVE-2019-17347: Fixed a PV kernel context switch corruption (XSA-293
bsc#1126201).

CVE-2019-18420: Fixed a hypervisor crash that could be caused by
malicious x86 PV guests, resulting in a denial of service (bsc#1154448
XSA-296).

CVE-2019-18421: Fixed a privilege escalation through malicious PV
guest administrators (bsc#1154458 XSA-299).

CVE-2019-18424: Fixed a privilege escalation through DMA to physical
devices by untrusted domains (bsc#1154461 XSA-302).

CVE-2019-18425: Fixed a privilege escalation from 32-bit PV guest used
mode (bsc#1154456 XSA-298).

CVE-2019-19577: Fixed an issue where a malicious guest administrator
could have caused Xen to access data structures while they are being
modified leading to a crash (bsc#1158007 XSA-311).

CVE-2019-19578: Fixed an issue where a malicious or buggy PV guest
could have caused hypervisor crash resulting in denial of service
affecting the entire host (bsc#1158005 XSA-309).

CVE-2019-19579: Fixed a privilege escalation where an untrusted domain
with access to a physical device can DMA into host memory (bsc#1157888
XSA-306).

CVE-2019-19580: Fixed a privilege escalation where a malicious PV
guest administrator could have been able to escalate their privilege
to that of the host (bsc#1158006 XSA-310).

CVE-2019-19581: Fixed a potential out of bounds on 32-bit Arm
(bsc#1158003 XSA-307).

CVE-2019-19583: Fixed improper checks which could have allowed HVM/PVH
guest userspace code to crash the guest, leading to a guest denial of
service (bsc#1158004 XSA-308).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1115045"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1126140"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1126141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1126192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1126195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1126196"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1126201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1135905"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1143797"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1145652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1146874"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1149813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1152497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1154448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1154456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1154458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1154461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1155945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158004"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1161181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12207/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19965/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11135/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-12067/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-12068/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-12155/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-14378/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-15890/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-17340/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-17341/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-17342/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-17343/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-17344/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-17347/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-18420/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-18421/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-18424/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-18425/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19577/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19578/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19579/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19580/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19581/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19583/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-7211/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200388-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?87d2932e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2020-388=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2020-388=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-4.5.5_28-22.64.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-debugsource-4.5.5_28-22.64.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-doc-html-4.5.5_28-22.64.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-kmp-default-4.5.5_28_k3.12.74_60.64.124-22.64.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.5.5_28_k3.12.74_60.64.124-22.64.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-libs-32bit-4.5.5_28-22.64.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-libs-4.5.5_28-22.64.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.5.5_28-22.64.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-libs-debuginfo-4.5.5_28-22.64.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-tools-4.5.5_28-22.64.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-tools-debuginfo-4.5.5_28-22.64.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-tools-domU-4.5.5_28-22.64.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-tools-domU-debuginfo-4.5.5_28-22.64.1")) flag++;


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
