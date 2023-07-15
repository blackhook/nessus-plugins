#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2541-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103412);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-10664", "CVE-2017-10806", "CVE-2017-11334", "CVE-2017-11434", "CVE-2017-12135", "CVE-2017-12137", "CVE-2017-12855", "CVE-2017-14316", "CVE-2017-14317", "CVE-2017-14319");

  script_name(english:"SUSE SLES12 Security Update : xen (SUSE-SU-2017:2541-1)");
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

  - CVE-2017-12135: Unbounded recursion in grant table code
    allowed a malicious guest to crash the host or
    potentially escalate privileges/leak information
    (XSA-226, bsc#1051787).

  - CVE-2017-12137: Incorrectly-aligned updates to
    pagetables allowed for privilege escalation (XSA-227,
    bsc#1051788).

  - CVE-2017-11334: The address_space_write_continue
    function in exec.c allowed local guest OS privileged
    users to cause a denial of service (out-of-bounds access
    and guest instance crash) by leveraging use of
    qemu_map_ram_ptr to access guest ram block area
    (bsc#1048920).

  - CVE-2017-11434: The dhcp_decode function in
    slirp/bootp.c allowed local guest OS users to cause a
    denial of service (out-of-bounds read) via a crafted
    DHCP options string (bsc#1049578).

  - CVE-2017-10806: Stack-based buffer overflow in
    hw/usb/redirect.c allowed local guest OS users to cause
    a denial of service via vectors related to logging debug
    messages (bsc#1047675).

  - CVE-2017-10664: qemu-nbd did not ignore SIGPIPE, which
    allowed remote attackers to cause a denial of service
    (daemon crash) by disconnecting during a
    server-to-client reply attempt (bsc#1046637).

  - CVE-2017-12855: Premature clearing of GTF_writing /
    GTF_reading lead to potentially leaking sensitive
    information (XSA-230, bsc#1052686).

  - CVE-2017-14316: Missing bound check in function
    `alloc_heap_pages` for an internal array allowed
    attackers using crafted hypercalls to execute arbitrary
    code within Xen (XSA-231, bsc#1056278)

  - CVE-2017-14317: A race in cxenstored may have cause a
    double-free allowind for DoS of the xenstored daemon
    (XSA-233, bsc#1056281).

  - CVE-2017-14319: An error while handling grant mappings
    allowed malicious or buggy x86 PV guest to escalate its
    privileges or crash the hypervisor (XSA-234,
    bsc#1056282).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1002573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1027519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1032598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1037413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1046637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1047675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1048920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1051787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1051788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10664/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10806/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11334/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11434/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12135/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12137/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12855/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14316/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14317/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14319/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172541-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?83112b17"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 12:zypper in -t patch
SUSE-SLE-SAP-12-2017-1576=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2017-1576=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-4.4.4_22-22.51.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-debugsource-4.4.4_22-22.51.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-doc-html-4.4.4_22-22.51.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-kmp-default-4.4.4_22_k3.12.61_52.89-22.51.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.4.4_22_k3.12.61_52.89-22.51.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-32bit-4.4.4_22-22.51.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-4.4.4_22-22.51.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.4.4_22-22.51.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-debuginfo-4.4.4_22-22.51.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-4.4.4_22-22.51.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-debuginfo-4.4.4_22-22.51.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-domU-4.4.4_22-22.51.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-domU-debuginfo-4.4.4_22-22.51.2")) flag++;


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
