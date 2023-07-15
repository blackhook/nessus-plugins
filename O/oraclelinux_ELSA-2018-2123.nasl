#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:2123 and 
# Oracle Linux Security Advisory ELSA-2018-2123 respectively.
#

include("compat.inc");

if (description)
{
  script_id(110918);
  script_version("1.3");
  script_cvs_date("Date: 2019/09/27 13:00:38");

  script_cve_id("CVE-2016-2183");
  script_xref(name:"RHSA", value:"2018:2123");

  script_name(english:"Oracle Linux 7 : python (ELSA-2018-2123)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2018:2123 :

An update for python is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Python is an interpreted, interactive, object-oriented programming
language, which includes modules, classes, exceptions, very high level
dynamic data types and dynamic typing. Python supports interfaces to
many system calls and libraries, as well as to various windowing
systems.

Security Fix(es) :

* A flaw was found in the way the DES/3DES cipher was used as part of
the TLS /SSL protocol. A man-in-the-middle attacker could use this
flaw to recover some plaintext data by capturing large amounts of
encrypted traffic between TLS/SSL server and client if the
communication used a DES/3DES based ciphersuite. (CVE-2016-2183)

Note: This update modifies the Python ssl module to disable 3DES
cipher suites by default.

Red Hat would like to thank OpenVPN for reporting this issue. Upstream
acknowledges Karthikeyan Bhargavan (Inria) and Gaetan Leurent (Inria)
as the original reporters."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-July/007865.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tkinter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/05");
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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python-2.7.5-69.0.1.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python-debug-2.7.5-69.0.1.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python-devel-2.7.5-69.0.1.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python-libs-2.7.5-69.0.1.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python-test-2.7.5-69.0.1.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python-tools-2.7.5-69.0.1.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"tkinter-2.7.5-69.0.1.el7_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python / python-debug / python-devel / python-libs / python-test / etc");
}
