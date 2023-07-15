#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:0377 and 
# CentOS Errata and Security Advisory 2018:0377 respectively.
#

include('compat.inc');

if (description)
{
  script_id(107269);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2018-5379");
  script_xref(name:"RHSA", value:"2018:0377");
  script_xref(name:"CEA-ID", value:"CEA-2019-0227");

  script_name(english:"CentOS 7 : quagga (CESA-2018:0377)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for quagga is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The quagga packages contain Quagga, the free network-routing software
suite that manages TCP/IP based protocols. Quagga supports the BGP4,
BGP4+, OSPFv2, OSPFv3, RIPv1, RIPv2, and RIPng protocols, and is
intended to be used as a Route Server and Route Reflector.

Security Fix(es) :

* quagga: Double free vulnerability in bgpd when processing certain
forms of UPDATE message allowing to crash or potentially execute
arbitrary code (CVE-2018-5379)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank the Quagga project for reporting this
issue.");
  # https://lists.centos.org/pipermail/centos-announce/2018-March/022790.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f351c9f");
  script_set_attribute(attribute:"solution", value:
"Update the affected quagga packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5379");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:quagga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:quagga-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:quagga-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"quagga-0.99.22.4-5.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"quagga-contrib-0.99.22.4-5.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"quagga-devel-0.99.22.4-5.el7_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "quagga / quagga-contrib / quagga-devel");
}
