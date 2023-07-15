#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0226.
#

include("compat.inc");

if (description)
{
  script_id(110306);
  script_version("1.6");
  script_cvs_date("Date: 2019/09/27 13:00:35");

  script_cve_id("CVE-2018-1124", "CVE-2018-1126");
  script_xref(name:"IAVA", value:"2018-A-0174");

  script_name(english:"OracleVM 3.3 / 3.4 : procps (OVMSA-2018-0226)");
  script_summary(english:"Checks the RPM output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - vmstat: fix invalid CPU utilization stats after vCPU
    hot-plug/unplug (Konrad Rzeszutek Wilk) [bug 18011019]

  - drop leftover assignment in fix for CVE-2018-1124
    causing a severe regression

  - Resolves: (CVE-2018-1124)

  - fix integer overflows leading to heap overflow in
    file2strvec

  - Resolves: CVE-2018-1124 (CVE-2018-1126)

  - ps: STIME no longer 1970 if many cores in /proc/stat

  - Resolves: rhbz#1460176

  - slabtop: additional work on usage computation to work on
    32bit archs

  - Related: rhbz#1330008

  - Removal of patch 92 -
    procps-3.2.8-pgrep-15-chars-warning.patch

  - Related: rhbz#877352

  - Rework of patch 91 from 3.2.8-37, stripping removed
    permanently, no new option

  - Resolves: rhbz#1322111

  - top: Termination with segfault if /proc becomes
    inaccessible during run

  - Resolves: rhbz#928724

  - sysctl manpage: Added explanation of conf files
    precedence

  - Resolves: rhbz#1217077

  - sysctl.conf manpage: new NOTES section with predefined
    vars hint

  - Resolves: rhbz#1318644

  - slabtop: fixing incorrect usage percent computation -
    int overflow

  - Resolves: rhbz#1330008

  - New warning if pattern exceeds 15 characters without -f
    option

  - Resolves: #877352

  - Adding option to skip stripping of wchan name data

  - Resolves: #1322111

  - #1201024 - [RFE] Increase sysctl -p line size limit

  - #1246573 - typo in ps man page

  - #1251101 - Fixing human readable patch (removing
    trailing spaces)

  - #1284076 - [RFE] Support for thread cgroups

  - #1288208 - use of /proc/self/auxv breaks ps when running
    as a different euid

  - #1288497 - pmap - no sums computed for RSS and Dirty
    column

  - Resolves: #1201024 #1246573 #1251101 #1284076 #1288208
    #1288497

  - #1262870 - Correctly skip vmflags (and other keys
    starting with A-Z)

  - Resolves: #1262870

  - #1246379 - free: values truncated to the column width

  - Resolves: #1246379

  - #1120580 - [RFE] Have sysctl -p read info from
    /etc/sysctl.d

  - Related: rhbz#1120580

  - #1120580 - [RFE] Have sysctl -p read info from
    /etc/sysctl.d

  - Related: rhbz#1120580

  - #993072 - Make the 'free' command a little more human
    friendly

  - #1172059 - ps coredump in stat2proc

  - #1120580 - [RFE] Have sysctl -p read info from
    /etc/sysctl.d

  - #1123311 - RFE: 'w' should have '-n' flag to suppress
    reverse name resolution of IP addresses

  - #1163404 - [procps] find_elf_note invalid read if setenv
    has been called before libproc init

  - Resolves: rhbz#993072 rhbz#1172059 rhbz#1120580
    rhbz#1123311 rhbz#1163404

  - #977467 - [RFE] Have sysctl -p read info from
    /etc/sysctl.d

  - Resolves: rhbz#977467

  - Reimplementing (#1060681) due to regressions

  - Related: rhbz#1060681

  - #1105125 - Locale dependent float delay in top and watch
    utilities

  - #1039013 - Include an API in RHEL to return the number
    of opened file descriptors for a process

  - Resolves: rhbz#1105125

  - Related: rhbz#1034337

  - #1060681 - ps -p cycles over all PIDs instead of just
    one

  - #963799 - Should shared memory be accounted in cached in
    free output?

  - Resolves: rhbz#1060681 rhbz#963799

  - #1089817 - Return value of pgrep is incorrect

  - #950748 - /lib64/libproc.so package both in procps and
    procps-devel

  - #1011216 - Backport man page fix of top utility - RES =
    CODE + DATA

  - #1082877 - top/man: RES - physical memory a task 'has
    used'->'is using'

  - #1034337 - Include man pages for openproc, readproc and
    readproctab

  - Resolves: rhbz#1089817 rhbz#950748 rhbz#1011216
    rhbz#1082877 rhbz#1034337"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2018-June/000861.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2018-June/000862.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected procps package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:procps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "(3\.3|3\.4)" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3 / 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"procps-3.2.8-45.0.1.el6_9.3")) flag++;

if (rpm_check(release:"OVS3.4", reference:"procps-3.2.8-45.0.1.el6_9.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "procps");
}
