#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0229 and 
# CentOS Errata and Security Advisory 2007:0229 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67042);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-4146");
  script_xref(name:"RHSA", value:"2007:0229");

  script_name(english:"CentOS 4 : gdb (CESA-2007:0229)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated gdb package that fixes a security issue and various bugs is
now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

GDB, the GNU debugger, allows debugging of programs written in C, C++,
and other languages by executing them in a controlled fashion and then
printing their data.

Various buffer overflows and underflows were found in the DWARF
expression computation stack in GDB. If a user loaded an executable
containing malicious debugging information into GDB, an attacker might
be able to execute arbitrary code with the privileges of the user.
(CVE-2006-4146)

This updated package also addresses the following issues :

* Fixed bogus 0x0 unwind of the thread's topmost function clone(3).

* Fixed deadlock accessing invalid address; for corrupted backtraces.

* Fixed a race which occasionally left the detached processes stopped.

* Fixed 'gcore' command for 32bit debugged processes on 64bit hosts.

* Added support for TLS 'errno' for threaded programs missing its
'-debuginfo' package..

* Suggest TLS 'errno' resolving by hand if no threading was found..

* Added a fix to prevent stepping into asynchronously invoked signal
handlers.

* Added a fix to avoid false warning on shared objects bfd close on
Itanium.

* Fixed segmentation fault on the source display by ^X 1.

* Fixed object names keyboard completion.

* Added a fix to avoid crash of 'info threads' if stale threads exist.

* Fixed a bug where shared libraries occasionally failed to load .

* Fixed handling of exec() called by a threaded debugged program.

* Fixed rebuilding requirements of the gdb package itself on multilib
systems.

* Fixed source directory pathname detection for the edit command.

All users of gdb should upgrade to this updated package, which
contains backported patches to resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013702.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a127d6e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gdb package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/02");
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
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"gdb-6.3.0.0-1.143.el4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdb");
}
