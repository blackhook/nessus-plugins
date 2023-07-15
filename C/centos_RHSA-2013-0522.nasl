#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0522 and 
# CentOS Errata and Security Advisory 2013:0522 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65153);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-4355");
  script_bugtraq_id(50829);
  script_xref(name:"RHSA", value:"2013:0522");

  script_name(english:"CentOS 6 : gdb (CESA-2013:0522)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gdb packages that fix one security issue and three bugs are
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The GNU Debugger (GDB) allows debugging of programs written in C, C++,
Java, and other languages by executing them in a controlled fashion
and then printing out their data.

GDB tried to auto-load certain files (such as GDB scripts, Python
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

* When a struct member was at an offset greater than 256 MB, the
resulting bit position within the struct overflowed and caused an
invalid memory access by GDB. With this update, the code has been
modified to ensure that GDB can access such positions. (BZ#795424)

* When a thread list of the core file became corrupted, GDB did not
print this list but displayed the 'Cannot find new threads: generic
error' error message instead. With this update, GDB has been modified
and it now prints the thread list of the core file as expected.
(BZ#811648)

* GDB did not properly handle debugging of multiple binaries with the
same build ID. This update modifies GDB to use symbolic links created
for particular binaries so that debugging of binaries that share a
build ID now proceeds as expected. Debugging of live programs and core
files is now more user-friendly. (BZ#836966)

All users of gdb are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019328.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d84329a2"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-February/000517.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ddb9e715"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gdb packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-4355");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdb-gdbserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/10");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"gdb-7.2-60.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gdb-gdbserver-7.2-60.el6")) flag++;


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
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdb / gdb-gdbserver");
}
