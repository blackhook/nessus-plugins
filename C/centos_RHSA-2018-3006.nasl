#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:3006 and 
# CentOS Errata and Security Advisory 2018:3006 respectively.
#

include('compat.inc');

if (description)
{
  script_id(118406);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/03");

  script_cve_id(
    "CVE-2018-12389",
    "CVE-2018-12390",
    "CVE-2018-12392",
    "CVE-2018-12393",
    "CVE-2018-12395",
    "CVE-2018-12396",
    "CVE-2018-12397"
  );
  script_xref(name:"RHSA", value:"2018:3006");

  script_name(english:"CentOS 6 : firefox (CESA-2018:3006)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for firefox is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Critical. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Mozilla Firefox is an open source web browser, designed for standards
compliance, performance, and portability.

This update upgrades Firefox to version 60.3.0 ESR.

Security Fix(es) :

* Mozilla: Memory safety bugs fixed in Firefox 63 and Firefox ESR 60.3
(CVE-2018-12390)

* Mozilla: Crash with nested event loops (CVE-2018-12392)

* Mozilla: Integer overflow during Unicode conversion while loading
JavaScript (CVE-2018-12393)

* Mozilla: WebExtension bypass of domain restrictions through header
rewriting (CVE-2018-12395)

* Mozilla: WebExtension content scripts can execute in disallowed
contexts (CVE-2018-12396)

* Mozilla: WebExtension local file permission check bypass
(CVE-2018-12397)

* Mozilla: Memory safety bugs fixed in Firefox ESR 60.3
(CVE-2018-12389)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Christian Holler, Bob Owen, Boris
Zbarsky, Calixte Denizet, Jason Kratzer, Jed Davis, Taegeon Lee,
Philipp, Ronald Crane, Raul Gurzau, Gary Kwong, Tyson Smith, Raymond
Forbes, Bogdan Tara, Nils, r, Rob Wu, Andrew Swan, and Daniel Veditz
as the original reporters.");
  # https://lists.centos.org/pipermail/centos-announce/2018-October/023070.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ecdb1cb");
  script_set_attribute(attribute:"solution", value:
"Update the affected firefox package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12392");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"firefox-60.3.0-1.el6.centos", allowmaj:TRUE)) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");
}
