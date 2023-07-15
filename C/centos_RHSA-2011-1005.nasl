#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1005 and 
# CentOS Errata and Security Advisory 2011:1005 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56263);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-3852");
  script_bugtraq_id(25380);
  script_xref(name:"RHSA", value:"2011:1005");

  script_name(english:"CentOS 5 : sysstat (CESA-2011:1005)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated sysstat package that fixes one security issue, various
bugs, and adds one enhancement is now available for Red Hat Enterprise
Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The sysstat package contains a set of utilities which enable system
monitoring of disks, network, and other I/O activity.

It was found that the sysstat initscript created a temporary file in
an insecure way. A local attacker could use this flaw to create
arbitrary files via a symbolic link attack. (CVE-2007-3852)

This update fixes the following bugs :

* On systems under heavy load, the sadc utility would sometimes output
the following error message if a write() call was unable to write all
of the requested input :

'Cannot write data to system activity file: Success.'

In this updated package, the sadc utility tries to write the remaining
input, resolving this issue. (BZ#454617)

* On the Itanium architecture, the 'sar -I' command provided incorrect
information about the interrupt statistics of the system. With this
update, the 'sar -I' command has been disabled for this architecture,
preventing this bug. (BZ#468340)

* Previously, the 'iostat -n' command used invalid data to create
statistics for read and write operations. With this update, the data
source for these statistics has been fixed, and the iostat utility now
returns correct information. (BZ#484439)

* The 'sar -d' command used to output invalid data about block
devices. With this update, the sar utility recognizes disk
registration and disk overflow statistics properly, and only correct
and relevant data is now displayed. (BZ#517490)

* Previously, the sar utility set the maximum number of days to be
logged in one month too high. Consequently, data from a month was
appended to data from the preceding month. With this update, the
maximum number of days has been set to 25, and data from a month now
correctly replaces data from the preceding month. (BZ#578929)

* In previous versions of the iostat utility, the number of NFS mount
points was hard-coded. Consequently, various issues occurred while
iostat was running and NFS mount points were mounted or unmounted;
certain values in iostat reports overflowed and some mount points were
not reported at all. With this update, iostat properly recognizes when
an NFS mount point mounts or unmounts, fixing these issues.
(BZ#675058, BZ#706095, BZ#694767)

* When a device name was longer than 13 characters, the iostat utility
printed a redundant new line character, making its output less
readable. This bug has been fixed and now, no extra characters are
printed if a long device name occurs in iostat output. (BZ#604637)

* Previously, if kernel interrupt counters overflowed, the sar utility
provided confusing output. This bug has been fixed and the sum of
interrupts is now reported correctly. (BZ#622557)

* When some processors were disabled on a multi-processor system, the
sar utility sometimes failed to provide information about the CPU
activity. With this update, the uptime of a single processor is used
to compute the statistics, rather than the total uptime of all
processors, and this bug no longer occurs. (BZ#630559)

* Previously, the mpstat utility wrongly interpreted data about
processors in the system. Consequently, it reported a processor that
did not exist. This bug has been fixed and non-existent CPUs are no
longer reported by mpstat. (BZ#579409)

* Previously, there was no easy way to enable the collection of
statistics about disks and interrupts. Now, the SADC_OPTIONS variable
can be used to set parameters for the sadc utility, fixing this bug.
(BZ#598794)

* The read_uptime() function failed to close its open file upon exit.
A patch has been provided to fix this bug. (BZ#696672)

This update also adds the following enhancement :

* With this update, the cifsiostat utility has been added to the
sysstat package to provide CIFS (Common Internet File System) mount
point I/O statistics. (BZ#591530)

All sysstat users are advised to upgrade to this updated package,
which contains backported patches to correct these issues and add this
enhancement."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/018036.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?446d555f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/018037.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e30798b0"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2011-September/000156.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e42a303"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2011-September/000157.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?073378f3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sysstat package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sysstat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"sysstat-7.0.2-11.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sysstat");
}
