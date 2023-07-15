#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:709 and 
# CentOS Errata and Security Advisory 2005:709 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67033);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-1704", "CVE-2005-1705");
  script_xref(name:"RHSA", value:"2005:709");

  script_name(english:"CentOS 4 : gdb (CESA-2005:709)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated gdb package that fixes several bugs and minor security
issues is now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

GDB, the GNU debugger, allows debugging of programs written in C, C++,
and other languages by executing them in a controlled fashion, then
printing their data.

Several integer overflow bugs were found in gdb. If a user is tricked
into processing a specially crafted executable file, it may allow the
execution of arbitrary code as the user running gdb. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-1704 to this issue.

A bug was found in the way gdb loads .gdbinit files. When a user
executes gdb, the local directory is searched for a .gdbinit file
which is then loaded. It is possible for a local user to execute
arbitrary commands as the victim running gdb by placing a malicious
.gdbinit file in a location where gdb may be run. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-1705 to this issue.

This updated package also addresses the following issues :

  - GDB on ia64 had previously implemented a bug fix to
    work-around a kernel problem when creating a core file
    via gcore. The bug fix caused a significant slow-down of
    gcore.

  - GDB on ia64 issued an extraneous warning when gcore was
    used.

  - GDB on ia64 could not backtrace over a sigaltstack.

  - GDB on ia64 could not successfully do an info frame for
    a signal trampoline.

  - GDB on AMD64 and Intel EM64T had problems attaching to a
    32-bit process.

  - GDB on AMD64 and Intel EM64T was not properly handling
    threaded watchpoints.

  - GDB could not build with gcc4 when -Werror flag was set.

  - GDB had problems printing inherited members of C++
    classes.

  - A few updates from mainline sources concerning Dwarf2
    partial die in cache support, follow-fork support,
    interrupted syscall support, and DW_OP_piece read
    support.

All users of gdb should upgrade to this updated package, which
resolves these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-October/012243.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26127f72"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gdb package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"gdb-6.3.0.0-1.63")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdb");
}
