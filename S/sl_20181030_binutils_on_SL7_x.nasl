#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(119179);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/01");

  script_cve_id("CVE-2018-10372", "CVE-2018-10373", "CVE-2018-10534", "CVE-2018-10535", "CVE-2018-13033", "CVE-2018-7208", "CVE-2018-7568", "CVE-2018-7569", "CVE-2018-7642", "CVE-2018-7643", "CVE-2018-8945");

  script_name(english:"Scientific Linux Security Update : binutils on SL7.x x86_64 (20181030)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Security Fix(es) :

  - binutils: Improper bounds check in
    coffgen.c:coff_pointerize_aux() allows for denial of
    service when parsing a crafted COFF file (CVE-2018-7208)

  - binutils: integer overflow via an ELF file with corrupt
    dwarf1 debug information in libbfd library
    (CVE-2018-7568)

  - binutils: integer underflow or overflow via an ELF file
    with a corrupt DWARF FORM block in libbfd library
    (CVE-2018-7569)

  - binutils: NULL pointer dereference in swap_std_reloc_in
    function in aoutx.h resulting in crash (CVE-2018-7642)

  - binutils: Integer overflow in the display_debug_ranges
    function resulting in crash (CVE-2018-7643)

  - binutils: Crash in elf.c:bfd_section_from_shdr() with
    crafted executable (CVE-2018-8945)

  - binutils: Heap-base buffer over-read in
    dwarf.c:process_cu_tu_index() allows for denial of
    service via crafted file (CVE-2018-10372)

  - binutils: NULL pointer dereference in
    dwarf2.c:concat_filename() allows for denial of service
    via crafted file (CVE-2018-10373)

  - binutils: out of bounds memory write in peXXigen.c files
    (CVE-2018-10534)

  - binutils: NULL pointer dereference in elf.c
    (CVE-2018-10535)

  - binutils: Uncontrolled Resource Consumption in execution
    of nm (CVE-2018-13033)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1811&L=scientific-linux-errata&F=&S=&P=4157
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4528db8f"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Update the affected binutils, binutils-debuginfo and / or
binutils-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:binutils-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"binutils-2.27-34.base.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"binutils-debuginfo-2.27-34.base.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"binutils-devel-2.27-34.base.el7")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils / binutils-debuginfo / binutils-devel");
}
