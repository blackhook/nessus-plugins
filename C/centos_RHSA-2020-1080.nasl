#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2020:1080 and 
# CentOS Errata and Security Advisory 2020:1080 respectively.
#

include("compat.inc");

if (description)
{
  script_id(135332);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/05");

  script_cve_id("CVE-2018-15587", "CVE-2019-3890");
  script_xref(name:"RHSA", value:"2020:1080");

  script_name(english:"CentOS 7 : atk / evolution / evolution-data-server / evolution-ews (CESA-2020:1080)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:1080 advisory.

  - evolution: specially crafted email leading to OpenPGP
    signatures being spoofed for arbitrary messages
    (CVE-2018-15587)

  - evolution-ews: all certificate errors ignored if error
    is ignored during initial account setup in gnome-online-
    accounts (CVE-2019-3890)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012408.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6f4e4fb9"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012441.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef2763a6"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012442.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f8c0771"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012443.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66ffcead"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3890");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:atk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:atk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-bogofilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-data-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-data-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-data-server-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-data-server-langpacks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-data-server-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-data-server-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-ews");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-ews-langpacks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-help");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-langpacks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-pst");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-spamassassin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"atk-2.28.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"atk-devel-2.28.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-3.28.5-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-bogofilter-3.28.5-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-data-server-3.28.5-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-data-server-devel-3.28.5-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-data-server-doc-3.28.5-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-data-server-langpacks-3.28.5-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-data-server-perl-3.28.5-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-data-server-tests-3.28.5-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-devel-3.28.5-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-devel-docs-3.28.5-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-ews-3.28.5-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-ews-langpacks-3.28.5-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-help-3.28.5-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-langpacks-3.28.5-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-pst-3.28.5-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evolution-spamassassin-3.28.5-8.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "atk / atk-devel / evolution / evolution-bogofilter / etc");
}
