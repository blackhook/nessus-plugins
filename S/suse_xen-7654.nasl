#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(57266);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2011-1898", "CVE-2011-1936");

  script_name(english:"SuSE 10 Security Update : Xen (ZYPP Patch Number 7654)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A security bug was fixed in Xen

  - A bug was found in the way Xen handles CPUID instruction
    emulation during VM exits. An unprivileged guest user
    can potentially use this flaw to crash the guest.
    (CVE-2011-1936)

This issue only affected systems running on x86 architecture with
Intel processor and VMX virtualization extension enabled."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1898.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1936.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7654.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-3.2.3_17040_37-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-devel-3.2.3_17040_37-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-doc-html-3.2.3_17040_37-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-doc-pdf-3.2.3_17040_37-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-doc-ps-3.2.3_17040_37-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-kmp-default-3.2.3_17040_37_2.6.16.60_0.87.9-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-kmp-smp-3.2.3_17040_37_2.6.16.60_0.87.9-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-libs-3.2.3_17040_37-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-tools-3.2.3_17040_37-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-tools-domU-3.2.3_17040_37-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-tools-ioemu-3.2.3_17040_37-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"xen-kmp-bigsmp-3.2.3_17040_37_2.6.16.60_0.87.9-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"xen-libs-32bit-3.2.3_17040_37-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-3.2.3_17040_37-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-devel-3.2.3_17040_37-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-doc-html-3.2.3_17040_37-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-doc-pdf-3.2.3_17040_37-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-doc-ps-3.2.3_17040_37-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-kmp-debug-3.2.3_17040_37_2.6.16.60_0.87.9-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-kmp-default-3.2.3_17040_37_2.6.16.60_0.87.9-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-kmp-kdump-3.2.3_17040_37_2.6.16.60_0.87.9-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-kmp-smp-3.2.3_17040_37_2.6.16.60_0.87.9-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-libs-3.2.3_17040_37-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-tools-3.2.3_17040_37-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-tools-domU-3.2.3_17040_37-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-tools-ioemu-3.2.3_17040_37-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-kmp-bigsmp-3.2.3_17040_37_2.6.16.60_0.87.9-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-kmp-kdumppae-3.2.3_17040_37_2.6.16.60_0.87.9-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-kmp-vmi-3.2.3_17040_37_2.6.16.60_0.87.9-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-kmp-vmipae-3.2.3_17040_37_2.6.16.60_0.87.9-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"xen-libs-32bit-3.2.3_17040_37-0.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
