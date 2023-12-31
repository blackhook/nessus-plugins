#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(49871);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-0598", "CVE-2009-4537");

  script_name(english:"SuSE 10 Security Update : Linux kernel (i386) (ZYPP Patch Number 7059)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This SUSE Linux Enterprise 10 SP3 kernel update fixes a severe
regression introduced by previous bugfix updates that would corrupt
NFSv4 mounted data.

The update also fixes several other bugs and following security 
issue :

  - drivers/net/r8169.c in the r8169 driver of Linux kernel
    2.6.32.3 and earlier does not properly check the size of
    an Ethernet frame that exceeds the maximum transmission
    unit (MTU), which allows remote attackers to.
    (CVE-2009-4537)

    1. cause a denial of service (temporary network outage)
    via a packet with a crafted size, in conjunction with
    certain packets containing A characters and certain
    packets containing E characters; or 2. cause a denial of
    service (system crash) via a packet with a crafted size,
    in conjunction with certain packets containing '0'
    characters, related to the value of the status register
    and erroneous behavior associated with the RxMaxSize
    register.

  - An information leak in 32bit emulation on x86_64
    machines could disclose sensitive information to local
    attackers. (CVE-2008-0598)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-0598.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4537.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7059.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.66.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"kernel-default-2.6.16.60-0.66.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"kernel-smp-2.6.16.60-0.66.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"kernel-source-2.6.16.60-0.66.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"kernel-syms-2.6.16.60-0.66.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"kernel-xen-2.6.16.60-0.66.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.66.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.66.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-debug-2.6.16.60-0.66.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-default-2.6.16.60-0.66.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-kdump-2.6.16.60-0.66.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-kdumppae-2.6.16.60-0.66.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-smp-2.6.16.60-0.66.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-source-2.6.16.60-0.66.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-syms-2.6.16.60-0.66.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-vmi-2.6.16.60-0.66.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-vmipae-2.6.16.60-0.66.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-xen-2.6.16.60-0.66.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.66.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
