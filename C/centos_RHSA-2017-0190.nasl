#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0190 and 
# CentOS Errata and Security Advisory 2017:0190 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(96813);
  script_version("3.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-5373", "CVE-2017-5375", "CVE-2017-5376", "CVE-2017-5378", "CVE-2017-5380", "CVE-2017-5383", "CVE-2017-5386", "CVE-2017-5390", "CVE-2017-5396");
  script_xref(name:"RHSA", value:"2017:0190");

  script_name(english:"CentOS 5 / 6 / 7 : firefox (CESA-2017:0190)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for firefox is now available for Red Hat Enterprise Linux 5,
Red Hat Enterprise Linux 6, and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Critical. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

[Updated 21 February 2017] This advisory has been updated to include
Firefox packages for the PPC and S390 architectures that were
previously omitted. For this revised update, packages for all
architectures were rebuilt. The rebuilt packages do not contain any
new code changes.

Mozilla Firefox is an open source web browser.

This update upgrades Firefox to version 45.7.0 ESR.

Security Fix(es) :

* Multiple flaws were found in the processing of malformed web
content. A web page containing malicious content could cause Firefox
to crash or, potentially, execute arbitrary code with the privileges
of the user running Firefox. (CVE-2017-5373, CVE-2017-5375,
CVE-2017-5376, CVE-2017-5378, CVE-2017-5380, CVE-2017-5383,
CVE-2017-5386, CVE-2017-5390, CVE-2017-5396)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Jann Horn, Filipe Gomes, Muneaki
Nishimura, Nils, Armin Razmjou, Christian Holler, Gary Kwong, Andre
Bargull, Jan de Mooij, Tom Schuster, Oriol, Rh0, Nicolas Gregoire, and
Jerri Rice as the original reporters."
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-February/022276.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bf8b1fcc"
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-February/022277.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ad8a178"
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-February/022278.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6f4242d2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5373");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x / 6.x / 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"firefox-45.7.0-2.el5.centos", allowmaj:TRUE)) flag++;

if (rpm_check(release:"CentOS-6", reference:"firefox-45.7.0-2.el6.centos", allowmaj:TRUE)) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"firefox-45.7.0-2.el7.centos", allowmaj:TRUE)) flag++;


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
