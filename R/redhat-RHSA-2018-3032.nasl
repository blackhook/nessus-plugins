#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:3032. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(118514);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/01");

  script_cve_id(
    "CVE-2018-7208",
    "CVE-2018-7568",
    "CVE-2018-7569",
    "CVE-2018-7642",
    "CVE-2018-7643",
    "CVE-2018-8945",
    "CVE-2018-10372",
    "CVE-2018-10373",
    "CVE-2018-10534",
    "CVE-2018-10535",
    "CVE-2018-13033"
  );
  script_xref(name:"RHSA", value:"2018:3032");

  script_name(english:"RHEL 7 : binutils (RHSA-2018:3032)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for binutils is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Low. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link (s) in the References section.

The binutils packages provide a collection of binary utilities for the
manipulation of object code in various object file formats. It
includes the ar, as, gprof, ld, nm, objcopy, objdump, ranlib, readelf,
size, strings, strip, and addr2line utilities.

Security Fix(es) :

* binutils: Improper bounds check in coffgen.c:coff_pointerize_aux()
allows for denial of service when parsing a crafted COFF file
(CVE-2018-7208)

* binutils: integer overflow via an ELF file with corrupt dwarf1 debug
information in libbfd library (CVE-2018-7568)

* binutils: integer underflow or overflow via an ELF file with a
corrupt DWARF FORM block in libbfd library (CVE-2018-7569)

* binutils: NULL pointer dereference in swap_std_reloc_in function in
aoutx.h resulting in crash (CVE-2018-7642)

* binutils: Integer overflow in the display_debug_ranges function
resulting in crash (CVE-2018-7643)

* binutils: Crash in elf.c:bfd_section_from_shdr() with crafted
executable (CVE-2018-8945)

* binutils: Heap-base buffer over-read in
dwarf.c:process_cu_tu_index() allows for denial of service via crafted
file (CVE-2018-10372)

* binutils: NULL pointer dereference in dwarf2.c:concat_filename()
allows for denial of service via crafted file (CVE-2018-10373)

* binutils: out of bounds memory write in peXXigen.c files
(CVE-2018-10534)

* binutils: NULL pointer dereference in elf.c (CVE-2018-10535)

* binutils: Uncontrolled Resource Consumption in execution of nm
(CVE-2018-13033)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.6 Release Notes linked from the References section.");
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3395ff0b");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:3032");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-7208");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-7568");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-7569");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-7642");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-7643");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-8945");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-10372");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-10373");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-10534");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-10535");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-13033");
  script_set_attribute(attribute:"solution", value:
"Update the affected binutils, binutils-debuginfo and / or
binutils-devel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7643");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:binutils-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:3032";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"binutils-2.27-34.base.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"binutils-2.27-34.base.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"binutils-debuginfo-2.27-34.base.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"binutils-devel-2.27-34.base.el7")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils / binutils-debuginfo / binutils-devel");
  }
}
