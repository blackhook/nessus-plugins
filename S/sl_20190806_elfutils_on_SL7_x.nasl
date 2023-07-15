#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(128214);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2018-16062", "CVE-2018-16402", "CVE-2018-16403", "CVE-2018-18310", "CVE-2018-18520", "CVE-2018-18521", "CVE-2019-7149", "CVE-2019-7150", "CVE-2019-7664", "CVE-2019-7665");

  script_name(english:"Scientific Linux Security Update : elfutils on SL7.x x86_64 (20190806)");
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
"The following packages have been upgraded to a later upstream version:
elfutils (0.176).

Security Fix(es) :

  - elfutils: Heap-based buffer over-read in
    libdw/dwarf_getaranges.c:dwarf_getaranges() via crafted
    file (CVE-2018-16062)

  - elfutils: Double-free due to double decompression of
    sections in crafted ELF causes crash (CVE-2018-16402)

  - elfutils: Heap-based buffer over-read in
    libdw/dwarf_getabbrev.c and libwd/dwarf_hasattr.c causes
    crash (CVE-2018-16403)

  - elfutils: invalid memory address dereference was
    discovered in dwfl_segment_report_module.c in libdwfl
    (CVE-2018-18310)

  - elfutils: eu-size cannot handle recursive ar files
    (CVE-2018-18520)

  - elfutils: Divide-by-zero in arlib_add_symbols function
    in arlib.c (CVE-2018-18521)

  - elfutils: heap-based buffer over-read in read_srclines
    in dwarf_getsrclines.c in libdw (CVE-2019-7149)

  - elfutils: segmentation fault in elf64_xlatetom in
    libelf/elf32_xlatetom.c (CVE-2019-7150)

  - elfutils: Out of bound write in elf_cvt_note in
    libelf/note_xlate.h (CVE-2019-7664)

  - elfutils: heap-based buffer over-read in function
    elf32_xlatetom in elf32_xlatetom.c (CVE-2019-7665)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1908&L=SCIENTIFIC-LINUX-ERRATA&P=22086
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d9aff1e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:elfutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:elfutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:elfutils-default-yama-scope");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:elfutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:elfutils-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:elfutils-libelf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:elfutils-libelf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:elfutils-libelf-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:elfutils-libs");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"elfutils-0.176-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"elfutils-debuginfo-0.176-2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"elfutils-default-yama-scope-0.176-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"elfutils-default-yama-scope-0.176-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"elfutils-devel-0.176-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"elfutils-devel-static-0.176-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"elfutils-libelf-0.176-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"elfutils-libelf-devel-0.176-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"elfutils-libelf-devel-static-0.176-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"elfutils-libs-0.176-2.el7")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "elfutils / elfutils-debuginfo / elfutils-default-yama-scope / etc");
}
