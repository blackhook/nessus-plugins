#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2684. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117468);
  script_version("1.6");
  script_cvs_date("Date: 2019/10/24 15:35:45");

  script_xref(name:"RHSA", value:"2018:2684");

  script_name(english:"RHEL 7 : dotNET (RHSA-2018:2684)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updates for rh-dotnet21 and rh-dotnet21-dotnet are now available for
.NET Core on Red Hat Enterprise Linux.

Red Hat Product Security has rated this update as having a security
impact of Low.

.NET Core is a managed software framework. It implements a subset of
the .NET framework APIs and several new APIs, and it includes a CLR
implementation.

A new version of .NET Core that addresses several security
vulnerabilities is now available. The updated version of the runtime
is 2.1.4. The updated version of the SDK is 2.1.402.

These versions correspond to the September 2018 security release by
.NET Core upstream projects.

Security Fix(es) :

Default inclusions for applications built with .NET Core have been
updated to reference the newest versions and their security fixes.

For more information, please refer to the upstream docs :

* .NET Core 2.1.4: https://github.com/dotnet/core/issues/1932"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:2684"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet21-dotnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet21-dotnet-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet21-dotnet-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet21-dotnet-runtime-2.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet21-dotnet-sdk-2.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet21-dotnet-sdk-2.1.4xx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet21-runtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:2684";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet21-2.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet21-dotnet-2.1.402-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet21-dotnet-debuginfo-2.1.402-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet21-dotnet-host-2.1.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet21-dotnet-runtime-2.1-2.1.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet21-dotnet-sdk-2.1-2.1.402-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet21-dotnet-sdk-2.1.4xx-2.1.402-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet21-runtime-2.1-3.el7")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rh-dotnet21 / rh-dotnet21-dotnet / rh-dotnet21-dotnet-debuginfo / etc");
  }
}
