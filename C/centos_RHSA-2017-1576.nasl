#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1576 and 
# CentOS Errata and Security Advisory 2017:1576 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101091);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-9462");
  script_xref(name:"RHSA", value:"2017:1576");

  script_name(english:"CentOS 6 / 7 : mercurial (CESA-2017:1576)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for mercurial is now available for Red Hat Enterprise Linux
6 and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Mercurial is a fast, lightweight source control management system
designed for efficient handling of very large distributed projects.

Security Fix(es) :

* A flaw was found in the way 'hg serve --stdio' command in Mercurial
handled command-line options. A remote, authenticated attacker could
use this flaw to execute arbitrary code on the Mercurial server by
using specially crafted command-line options. (CVE-2017-9462)"
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-June/022471.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb423136"
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-June/022488.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f8dc9155"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mercurial packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9462");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mercurial Custom hg-ssh Wrapper Remote Code Exec');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:emacs-mercurial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:emacs-mercurial-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mercurial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mercurial-hgk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/29");
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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x / 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"emacs-mercurial-1.4-5.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"emacs-mercurial-el-1.4-5.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mercurial-1.4-5.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mercurial-hgk-1.4-5.el6_9")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"emacs-mercurial-2.6.2-7.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"emacs-mercurial-el-2.6.2-7.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mercurial-2.6.2-7.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mercurial-hgk-2.6.2-7.el7_3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs-mercurial / emacs-mercurial-el / mercurial / mercurial-hgk");
}
