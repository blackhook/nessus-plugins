#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:13921-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(121004);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-13672", "CVE-2018-10839", "CVE-2018-17958", "CVE-2018-17962", "CVE-2018-17963", "CVE-2018-18438", "CVE-2018-18849", "CVE-2018-19665", "CVE-2018-19961", "CVE-2018-19962", "CVE-2018-19965", "CVE-2018-19966", "CVE-2018-19967");

  script_name(english:"SUSE SLES11 Security Update : xen (SUSE-SU-2019:13921-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xen fixes the following issues :

Security vulnerabilities fixed :

CVE-2018-19961, CVE-2018-19962: Fixed an issue related to insufficient
TLB flushing with AMD IOMMUs, which potentially allowed a guest to
escalate its privileges, may cause a Denial of Service (DoS) affecting
the entire host, or may be able to access data it is not supposed to
access. (XSA-275) (bsc#1115040)

CVE-2018-19965: Fixed an issue related to the INVPCID instruction in
case non-canonical addresses are accessed, which may allow a guest to
cause Xen to crash, resulting in a Denial of Service (DoS) affecting
the entire host. (XSA-279) (bsc#1115045)

CVE-2018-19966: Fixed an issue related to a previous fix for XSA-240,
which conflicted with shadow paging and allowed a guest to cause Xen
to crash, resulting in a Denial of Service (DoS) (XSA-280)
(bsc#1115047)

CVE-2018-19967: Fixed HLE constructs that allowed guests to lock up
the host, resulting in a Denial of Service (DoS). (XSA-282)
(bsc#1114988)

CVE-2018-19665: Fixed an integer overflow resulting in memory
corruption in various Bluetooth functions, allowing this to crash qemu
process resulting in Denial of Service (DoS). (bsc#1117756).

CVE-2018-18849: Fixed an out of bounds memory access in the LSI53C895A
SCSI host bus adapter emulation, which allowed a user and/or process
to crash the qemu process resulting in a Denial of Service (DoS).
(bsc#1114423)

Fixed an integer overflow in ccid_card_vscard_read(), which allowed
for memory corruption. (bsc#1112188)

CVE-2017-13672: Fixed an out of bounds read access during display
update (bsc#1056336)

CVE-2018-17958: Fixed an integer overflow leading to a buffer overflow
in the rtl8139 component (bsc#1111007)

CVE-2018-17962: Fixed an integer overflow leading to a buffer overflow
in the pcnet component (bsc#1111011)

CVE-2018-17963: Fixed an integer overflow in relation to large packet
sizes, leading to a denial of service (DoS). (bsc#1111014)

CVE-2018-10839: Fixed an integer overflow leading to a buffer overflow
in the ne2000 component (bsc#1110924)

Other bugs fixed: Fixed an issue related to a domU hang on SLE12-SP3
HV (bsc#1108940)

Upstream bug fixes (bsc#1027519)

Fixed crashing VMs when migrating between dom0 hosts (bsc#1031382)

Fixed an issue with xpti=no-dom0 not working as expected (bsc#1105528)

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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1031382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1105528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1108940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1110924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1111007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1111011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1111014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1114423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1114988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1115040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1115045"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1115047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1117756"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13672/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10839/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-17958/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-17962/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-17963/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-18438/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-18849/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19665/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19961/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19962/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19965/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19966/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19967/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-201913921-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a7a12fa"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-xen-13921=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-xen-13921=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-xen-13921=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-kmp-default-4.4.4_38_3.0.101_108.84-61.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-libs-4.4.4_38-61.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-tools-domU-4.4.4_38-61.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-4.4.4_38-61.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-doc-html-4.4.4_38-61.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-libs-32bit-4.4.4_38-61.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-tools-4.4.4_38-61.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-kmp-pae-4.4.4_38_3.0.101_108.84-61.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"xen-kmp-default-4.4.4_38_3.0.101_108.84-61.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"xen-libs-4.4.4_38-61.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"xen-tools-domU-4.4.4_38-61.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"xen-kmp-pae-4.4.4_38_3.0.101_108.84-61.40.1")) flag++;


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
