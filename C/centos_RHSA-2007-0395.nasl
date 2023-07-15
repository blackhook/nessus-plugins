#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0395 and 
# CentOS Errata and Security Advisory 2007:0395 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25526);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-1349");
  script_bugtraq_id(23192);
  script_xref(name:"RHSA", value:"2007:0395");

  script_name(english:"CentOS 3 / 4 / 5 : mod_perl (CESA-2007:0395)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mod_perl packages that fix a security issue are now available
for Red Hat Enterprise Linux 3, 4, 5.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

Mod_perl incorporates a Perl interpreter into the Apache web server,
so that the Apache web server can directly execute Perl code.

An issue was found in the 'namespace_from_uri' method of the
ModPerl::RegistryCooker class. If a server implemented a mod_perl
registry module using this method, a remote attacker requesting a
carefully crafted URI can cause resource consumption, which could lead
to a denial of service (CVE-2007-1349).

Users of mod_perl should update to these erratum packages which
contain a backported fix to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013933.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e4cef8ca"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013934.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?833a1438"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013935.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?88f82cff"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013936.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8fc48536"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013943.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3fd0553f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013944.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?06914f8f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013967.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c62cec9a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013968.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7bfa8728"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mod_perl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_perl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"mod_perl-1.99_09-12.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mod_perl-devel-1.99_09-12.ent")) flag++;

if (rpm_check(release:"CentOS-4", reference:"mod_perl-1.99_16-4.5")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mod_perl-devel-1.99_16-4.5")) flag++;

if (rpm_check(release:"CentOS-5", reference:"mod_perl-2.0.2-6.3.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mod_perl-devel-2.0.2-6.3.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod_perl / mod_perl-devel");
}
