#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0221 and 
# CentOS Errata and Security Advisory 2014:0221 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72865);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-0060", "CVE-2014-0061", "CVE-2014-0062", "CVE-2014-0063", "CVE-2014-0064", "CVE-2014-0065", "CVE-2014-0066", "CVE-2014-2669");
  script_xref(name:"RHSA", value:"2014:0221");

  script_name(english:"CentOS 6 : postgresql92-postgresql (CESA-2014:0221)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote CentOS host is missing a security update which has been
documented in Red Hat advisory RHSA-2014:0221."
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-February/020182.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5bdd8abe"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql92-postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0061");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:postgresql92-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:postgresql92-postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:postgresql92-postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:postgresql92-postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:postgresql92-postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:postgresql92-postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:postgresql92-postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:postgresql92-postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:postgresql92-postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:postgresql92-postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:postgresql92-postgresql-upgrade");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"postgresql92-postgresql-9.2.7-1.1.el6.centos.alt")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"postgresql92-postgresql-contrib-9.2.7-1.1.el6.centos.alt")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"postgresql92-postgresql-devel-9.2.7-1.1.el6.centos.alt")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"postgresql92-postgresql-docs-9.2.7-1.1.el6.centos.alt")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"postgresql92-postgresql-libs-9.2.7-1.1.el6.centos.alt")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"postgresql92-postgresql-plperl-9.2.7-1.1.el6.centos.alt")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"postgresql92-postgresql-plpython-9.2.7-1.1.el6.centos.alt")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"postgresql92-postgresql-pltcl-9.2.7-1.1.el6.centos.alt")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"postgresql92-postgresql-server-9.2.7-1.1.el6.centos.alt")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"postgresql92-postgresql-test-9.2.7-1.1.el6.centos.alt")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"postgresql92-postgresql-upgrade-9.2.7-1.1.el6.centos.alt")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql92-postgresql / postgresql92-postgresql-contrib / etc");
}
