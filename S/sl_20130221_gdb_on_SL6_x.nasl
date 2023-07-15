#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(64951);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-4355");

  script_name(english:"Scientific Linux Security Update : gdb on SL6.x i386/x86_64 (20130221)");
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
"GDB tried to auto-load certain files (such as GDB scripts, Python
scripts, and a thread debugging library) from the current working
directory when debugging programs. This could result in the execution
of arbitrary code with the user's privileges when GDB was run in a
directory that has untrusted content. (CVE-2011-4355)

With this update, GDB no longer auto-loads files from the current
directory and only trusts certain system directories by default. The
list of trusted directories can be viewed and modified using the 'show
auto-load safe-path' and 'set auto-load safe-path' GDB commands. Refer
to the GDB manual, linked to in the References, for further
information.

This update also fixes the following bugs :

  - When a struct member was at an offset greater than 256
    MB, the resulting bit position within the struct
    overflowed and caused an invalid memory access by GDB.
    With this update, the code has been modified to ensure
    that GDB can access such positions.

  - When a thread list of the core file became corrupted,
    GDB did not print this list but displayed the 'Cannot
    find new threads: generic error' error message instead.
    With this update, GDB has been modified and it now
    prints the thread list of the core file as expected.

  - GDB did not properly handle debugging of multiple
    binaries with the same build ID. This update modifies
    GDB to use symbolic links created for particular
    binaries so that debugging of binaries that share a
    build ID now proceeds as expected. Debugging of live
    programs and core files is now more user-friendly."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1302&L=scientific-linux-errata&T=0&P=5282
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6da2811"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected gdb, gdb-debuginfo and / or gdb-gdbserver
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gdb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gdb-gdbserver");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"gdb-7.2-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gdb-debuginfo-7.2-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gdb-gdbserver-7.2-60.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdb / gdb-debuginfo / gdb-gdbserver");
}
