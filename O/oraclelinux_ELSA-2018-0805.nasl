#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:0805 and 
# Oracle Linux Security Advisory ELSA-2018-0805 respectively.
#

include("compat.inc");

if (description)
{
  script_id(109105);
  script_version("1.4");
  script_cvs_date("Date: 2019/09/27 13:00:38");

  script_cve_id("CVE-2014-9402", "CVE-2015-5180", "CVE-2017-12132", "CVE-2017-15670", "CVE-2017-15804", "CVE-2018-1000001");
  script_xref(name:"RHSA", value:"2018:0805");

  script_name(english:"Oracle Linux 7 : glibc (ELSA-2018-0805)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2018:0805 :

An update for glibc is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The glibc packages provide the standard C libraries (libc), POSIX
thread libraries (libpthread), standard math libraries (libm), and the
name service cache daemon (nscd) used by multiple programs on the
system. Without these libraries, the Linux system cannot function
correctly.

Security Fix(es) :

* glibc: realpath() buffer underflow when getcwd() returns relative
path allows privilege escalation (CVE-2018-1000001)

* glibc: Buffer overflow in glob with GLOB_TILDE (CVE-2017-15670)

* glibc: Buffer overflow during unescaping of user names with the ~
operator (CVE-2017-15804)

* glibc: denial of service in getnetbyname function (CVE-2014-9402)

* glibc: DNS resolver NULL pointer dereference with crafted record
type (CVE-2015-5180)

* glibc: Fragmentation attacks possible when EDNS0 is enabled
(CVE-2017-12132)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank halfdog for reporting CVE-2018-1000001.
The CVE-2015-5180 issue was discovered by Florian Weimer (Red Hat
Product Security).

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.5 Release Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-April/007611.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'glibc "realpath()" Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glibc-2.17-222.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glibc-common-2.17-222.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glibc-devel-2.17-222.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glibc-headers-2.17-222.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glibc-static-2.17-222.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glibc-utils-2.17-222.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nscd-2.17-222.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-devel / glibc-headers / glibc-static / etc");
}
