#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:659 and 
# CentOS Errata and Security Advisory 2005:659 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21848);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-1704");
  script_xref(name:"RHSA", value:"2005:659");

  script_name(english:"CentOS 3 : binutils (CESA-2005:659)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated binutils package that fixes several bugs and minor security
issues is now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

Binutils is a collection of utilities used for the creation of
executable code. A number of bugs were found in various binutils
tools.

Several integer overflow bugs were found in binutils. If a user is
tricked into processing a specially crafted executable with utilities
such as readelf, size, strings, objdump, or nm, it may allow the
execution of arbitrary code as the user running the utility. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-1704 to this issue.

Additionally, the following bugs have been fixed :

-- correct alignment of .tbss section if the requested alignment of
.tbss is bigger than requested alignment of .tdata section -- by
default issue an error if IA-64 hint@pause instruction is put into the
B slot, add assembler command line switch to override this behaviour

All users of binutils should upgrade to this updated package, which
contains backported patches to resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012212.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b8893ef"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012231.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?27856d56"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012232.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0da8da0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected binutils package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:binutils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"binutils-2.14.90.0.4-39")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils");
}
