#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0142 and 
# Oracle Linux Security Advisory ELSA-2010-0142 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68009);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-0624");
  script_bugtraq_id(38628);
  script_xref(name:"RHSA", value:"2010:0142");

  script_name(english:"Oracle Linux 3 : tar (ELSA-2010-0142)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0142 :

An updated tar package that fixes one security issue is now available
for Red Hat Enterprise Linux 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The GNU tar program saves many files together in one archive and can
restore individual files (or all of the files) from that archive.

A heap-based buffer overflow flaw was found in the way tar expanded
archive files. If a user were tricked into expanding a specially
crafted archive, it could cause the tar executable to crash or execute
arbitrary code with the privileges of the user running tar.
(CVE-2010-0624)

Red Hat would like to thank Jakob Lell for responsibly reporting this
issue.

Users of tar are advised to upgrade to this updated package, which
contains a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-March/001389.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tar package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tar");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"tar-1.13.25-16.RHEL3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"tar-1.13.25-16.RHEL3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tar");
}
