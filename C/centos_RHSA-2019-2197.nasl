#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2197 and 
# CentOS Errata and Security Advisory 2019:2197 respectively.
#

include("compat.inc");

if (description)
{
  script_id(128375);
  script_version("1.3");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2018-16062", "CVE-2018-16402", "CVE-2018-16403", "CVE-2018-18310", "CVE-2018-18520", "CVE-2018-18521", "CVE-2019-7149", "CVE-2019-7150", "CVE-2019-7664", "CVE-2019-7665");
  script_xref(name:"RHSA", value:"2019:2197");

  script_name(english:"CentOS 7 : elfutils (CESA-2019:2197)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for elfutils is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Low. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link (s) in the References section.

The elfutils packages contain a number of utility programs and
libraries related to the creation and maintenance of executable code.

The following packages have been upgraded to a later upstream version:
elfutils (0.176). (BZ#1676504)

Security Fix(es) :

* elfutils: Heap-based buffer over-read in libdw/
dwarf_getaranges.c:dwarf_getaranges() via crafted file
(CVE-2018-16062)

* elfutils: Double-free due to double decompression of sections in
crafted ELF causes crash (CVE-2018-16402)

* elfutils: Heap-based buffer over-read in libdw/dwarf_getabbrev.c and
libwd/ dwarf_hasattr.c causes crash (CVE-2018-16403)

* elfutils: invalid memory address dereference was discovered in
dwfl_segment_report_module.c in libdwfl (CVE-2018-18310)

* elfutils: eu-size cannot handle recursive ar files (CVE-2018-18520)

* elfutils: Divide-by-zero in arlib_add_symbols function in arlib.c
(CVE-2018-18521)

* elfutils: heap-based buffer over-read in read_srclines in
dwarf_getsrclines.c in libdw (CVE-2019-7149)

* elfutils: segmentation fault in elf64_xlatetom in
libelf/elf32_xlatetom.c (CVE-2019-7150)

* elfutils: Out of bound write in elf_cvt_note in libelf/note_xlate.h
(CVE-2019-7664)

* elfutils: heap-based buffer over-read in function elf32_xlatetom in
elf32_xlatetom.c (CVE-2019-7665)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.7 Release Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/005856.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?296c7414"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected elfutils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16402");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:elfutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:elfutils-default-yama-scope");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:elfutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:elfutils-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:elfutils-libelf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:elfutils-libelf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:elfutils-libelf-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:elfutils-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"elfutils-0.176-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"elfutils-default-yama-scope-0.176-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"elfutils-devel-0.176-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"elfutils-devel-static-0.176-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"elfutils-libelf-0.176-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"elfutils-libelf-devel-0.176-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"elfutils-libelf-devel-static-0.176-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"elfutils-libs-0.176-2.el7")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "elfutils / elfutils-default-yama-scope / elfutils-devel / etc");
}
