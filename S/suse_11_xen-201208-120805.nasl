#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(64235);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2012-2625", "CVE-2012-3432", "CVE-2012-3433");

  script_name(english:"SuSE 11.2 Security Update : Xen and libvirt (SAT Patch Number 6640)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Xen was updated to fix several security issues :

  - A xen HVM guest destroy p2m teardown host DoS
    vulnerability was fixed, where malicious guest could
    lock/crash the host. (CVE-2012-3433)

  - A xen HVM guest user mode MMIO emulation DoS was fixed.
    (CVE-2012-3432)

  - The xen pv bootloader doesn't check the size of the
    bzip2 or lzma compressed kernel, leading to denial of
    service (crash). (CVE-2012-2625)

Also the following bug in XEN has been fixed :

  - Xen HVM DomU crash during Windows Server 2008 R2
    install, when maxmem > memory This update also included
    bugfixes for:. (bnc#746702)

  - vm-install: - bnc#762963 - ReaR: Unable to recover a
    paravirtualized XEN guest

  - virt-manager - SLE11-SP2 ONLY

  - virt-manager fails to start after upgrade to SLES11 SP2
    from SLES10. (bnc#764982)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=746702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762963"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=764982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=766283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2625.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3432.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3433.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 6640.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libvirt-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libvirt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:virt-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:vm-install");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libvirt-0.9.6-0.21.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libvirt-client-0.9.6-0.21.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libvirt-client-32bit-0.9.6-0.21.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libvirt-doc-0.9.6-0.21.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libvirt-python-0.9.6-0.21.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"virt-manager-0.9.0-3.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"vm-install-0.5.10-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-4.1.2_20-0.5.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-doc-html-4.1.2_20-0.5.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-doc-pdf-4.1.2_20-0.5.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-kmp-default-4.1.2_20_3.0.38_0.5-0.5.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-kmp-trace-4.1.2_20_3.0.38_0.5-0.5.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-libs-4.1.2_20-0.5.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-libs-32bit-4.1.2_20-0.5.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-tools-4.1.2_20-0.5.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-tools-domU-4.1.2_20-0.5.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libvirt-0.9.6-0.21.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libvirt-client-0.9.6-0.21.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libvirt-client-32bit-0.9.6-0.21.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libvirt-doc-0.9.6-0.21.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libvirt-python-0.9.6-0.21.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"virt-manager-0.9.0-3.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"vm-install-0.5.10-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-4.1.2_20-0.5.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-doc-html-4.1.2_20-0.5.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-doc-pdf-4.1.2_20-0.5.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-kmp-default-4.1.2_20_3.0.38_0.5-0.5.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-kmp-trace-4.1.2_20_3.0.38_0.5-0.5.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-libs-4.1.2_20-0.5.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-libs-32bit-4.1.2_20-0.5.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-tools-4.1.2_20-0.5.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-tools-domU-4.1.2_20-0.5.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
