#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:0109 and 
# CentOS Errata and Security Advisory 2019:0109 respectively.
#

include("compat.inc");

if (description)
{
  script_id(121371);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/20");

  script_cve_id("CVE-2018-18311");
  script_xref(name:"RHSA", value:"2019:0109");

  script_name(english:"CentOS 7 : perl (CESA-2019:0109)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for perl is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Perl is a high-level programming language that is commonly used for
system administration utilities and web programming.

Security Fix(es) :

* perl: Integer overflow leading to buffer overflow in
Perl_my_setenv() (CVE-2018-18311)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank the Perl project for reporting this issue.
Upstream acknowledges Jayakrishna Menon as the original reporter."
  );
  # https://lists.centos.org/pipermail/centos-announce/2019-January/023148.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fab7d101"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected perl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-18311");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-CPAN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-ExtUtils-CBuilder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-ExtUtils-Embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-ExtUtils-Install");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-IO-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-Locale-Maketext-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-Module-CoreList");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-Module-Loaded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-Object-Accessor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-Package-Constants");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-Pod-Escapes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-Time-Piece");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-tests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perl-5.16.3-294.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perl-CPAN-1.9800-294.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perl-ExtUtils-CBuilder-0.28.2.6-294.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perl-ExtUtils-Embed-1.30-294.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perl-ExtUtils-Install-1.58-294.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perl-IO-Zlib-1.10-294.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perl-Locale-Maketext-Simple-0.21-294.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perl-Module-CoreList-2.76.02-294.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perl-Module-Loaded-0.08-294.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perl-Object-Accessor-0.42-294.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perl-Package-Constants-0.02-294.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perl-Pod-Escapes-1.04-294.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perl-Time-Piece-1.20.1-294.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perl-core-5.16.3-294.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perl-devel-5.16.3-294.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perl-libs-5.16.3-294.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perl-macros-5.16.3-294.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perl-tests-5.16.3-294.el7_6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl / perl-CPAN / perl-ExtUtils-CBuilder / perl-ExtUtils-Embed / etc");
}
