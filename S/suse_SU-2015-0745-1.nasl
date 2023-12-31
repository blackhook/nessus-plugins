#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0745-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(83718);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-2044", "CVE-2015-2045", "CVE-2015-2151", "CVE-2015-2756");
  script_bugtraq_id(72577, 72954, 72955, 73015);

  script_name(english:"SUSE SLES11 Security Update : Xen (SUSE-SU-2015:0745-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Virtualization service XEN was updated to fix various bugs and
security issues.

The following security issues have been fixed :

CVE-2015-2756: XSA-126: Unmediated PCI command register access in qemu
could have lead to denial of service attacks against the host, if PCI
cards are passed through to guests.

XSA-125: Long latency MMIO mapping operations were not preemptible.

CVE-2015-2151: XSA-123: Instructions with register operands ignored
eventual segment overrides encoded for them. Due to an insufficiently
conditional assignment such a bogus segment override could have,
however, corrupted a pointer used subsequently to store the result of
the instruction.

CVE-2015-2045: XSA-122: The code handling certain sub-operations of
the HYPERVISOR_xen_version hypercall failed to fully initialize all
fields of structures subsequently copied back to guest memory. Due to
this hypervisor stack contents were copied into the destination of the
operation, thus becoming visible to the guest.

CVE-2015-2044: XSA-121: Emulation routines in the hypervisor dealing
with certain system devices checked whether the access size by the
guest is a supported one. When the access size is unsupported these
routines failed to set the data to be returned to the guest for read
accesses, so that hypervisor stack contents were copied into the
destination of the operation, thus becoming visible to the guest.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150745-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64a21e31"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11 SP1 LTSS :

zypper in -t patch slessp1-xen-201503=10562

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES11" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-4.0.3_21548_18-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-doc-html-4.0.3_21548_18-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-doc-pdf-4.0.3_21548_18-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-kmp-default-4.0.3_21548_18_2.6.32.59_0.19-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-kmp-trace-4.0.3_21548_18_2.6.32.59_0.19-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-libs-4.0.3_21548_18-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-tools-4.0.3_21548_18-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-tools-domU-4.0.3_21548_18-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-kmp-pae-4.0.3_21548_18_2.6.32.59_0.19-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-4.0.3_21548_18-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-doc-html-4.0.3_21548_18-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-doc-pdf-4.0.3_21548_18-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-kmp-default-4.0.3_21548_18_2.6.32.59_0.19-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-kmp-trace-4.0.3_21548_18_2.6.32.59_0.19-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-libs-4.0.3_21548_18-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-tools-4.0.3_21548_18-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-tools-domU-4.0.3_21548_18-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-kmp-pae-4.0.3_21548_18_2.6.32.59_0.19-0.15.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Xen");
}
