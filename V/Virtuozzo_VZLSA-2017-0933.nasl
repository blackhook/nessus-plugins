#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101449);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2016-8650",
    "CVE-2016-9793",
    "CVE-2017-2618",
    "CVE-2017-2636"
  );

  script_name(english:"Virtuozzo 7 : kernel / kernel-abi-whitelists / kernel-debug / etc (VZLSA-2017-0933)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for kernel is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

These updated kernel packages include several security issues and
numerous bug fixes. Space precludes documenting all of these bug fixes
in this advisory. To see the complete list of bug fixes, users are
directed to the related Knowledge Article:
https://access.redhat.com/articles/2986951.

Security Fix(es) :

* A race condition flaw was found in the N_HLDC Linux kernel driver
when accessing n_hdlc.tbuf list that can lead to double free. A local,
unprivileged user able to set the HDLC line discipline on the tty
device could use this flaw to increase their privileges on the system.
(CVE-2017-2636, Important)

* A flaw was found in the Linux kernel key management subsystem in
which a local attacker could crash the kernel or corrupt the stack and
additional memory (denial of service) by supplying a specially crafted
RSA key. This flaw panics the machine during the verification of the
RSA key. (CVE-2016-8650, Moderate)

* A flaw was found in the Linux kernel's implementation of setsockopt
for the SO_{SND|RCV}BUFFORCE setsockopt() system call. Users with
non-namespace CAP_NET_ADMIN are able to trigger this call and create a
situation in which the sockets sendbuff data size could be negative.
This could adversely affect memory allocations and create situations
where the system could crash or cause memory corruption.
(CVE-2016-9793, Moderate)

* A flaw was found in the Linux kernel's handling of clearing SELinux
attributes on /proc/pid/attr files. An empty (null) write to this file
can crash the system by causing the system to attempt to access
unmapped kernel memory. (CVE-2017-2618, Moderate)

Red Hat would like to thank Alexander Popov for reporting
CVE-2017-2636 and Ralf Spenneberg for reporting CVE-2016-8650. The
CVE-2017-2618 issue was discovered by Paul Moore (Red Hat
Engineering).

Note that Tenable Network Security has attempted to extract the
preceding description block directly from the corresponding Red Hat
security advisory. Virtuozzo provides no description for VZLSA
advisories. Tenable has attempted to automatically clean and format
it as much as possible without introducing additional issues.");
  # http://repo.virtuozzo.com/vzlinux/announcements/json/VZLSA-2017-0933.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96946551");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017-0933");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel / kernel-abi-whitelists / kernel-debug / etc package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:7");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Virtuozzo/release", "Host/Virtuozzo/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Virtuozzo/release");
if (isnull(release) || "Virtuozzo" >!< release) audit(AUDIT_OS_NOT, "Virtuozzo");
os_ver = pregmatch(pattern: "Virtuozzo Linux release ([0-9]+\.[0-9])(\D|$)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 7.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-514.16.1.vl7",
        "kernel-abi-whitelists-3.10.0-514.16.1.vl7",
        "kernel-debug-3.10.0-514.16.1.vl7",
        "kernel-debug-devel-3.10.0-514.16.1.vl7",
        "kernel-devel-3.10.0-514.16.1.vl7",
        "kernel-doc-3.10.0-514.16.1.vl7",
        "kernel-headers-3.10.0-514.16.1.vl7",
        "kernel-tools-3.10.0-514.16.1.vl7",
        "kernel-tools-libs-3.10.0-514.16.1.vl7",
        "kernel-tools-libs-devel-3.10.0-514.16.1.vl7",
        "perf-3.10.0-514.16.1.vl7",
        "python-perf-3.10.0-514.16.1.vl7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-7", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / etc");
}
