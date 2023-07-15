#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2771 and 
# CentOS Errata and Security Advisory 2017:2771 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103362);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-14482");
  script_xref(name:"RHSA", value:"2017:2771");

  script_name(english:"CentOS 7 : emacs (CESA-2017:2771)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for emacs is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

GNU Emacs is a powerful, customizable, self-documenting text editor.
It provides special code editing features, a scripting language
(elisp), and the capability to read e-mail and news.

Security Fix(es) :

* A command injection flaw within the Emacs 'enriched mode' handling
has been discovered. By tricking an unsuspecting user into opening a
specially crafted file using Emacs, a remote attacker could exploit
this flaw to execute arbitrary commands with the privileges of the
Emacs user. (CVE-2017-14482)"
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-September/022541.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ada4ce14"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected emacs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14482");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:emacs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:emacs-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:emacs-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:emacs-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:emacs-terminal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/21");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"emacs-24.3-20.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"emacs-common-24.3-20.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"emacs-el-24.3-20.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"emacs-filesystem-24.3-20.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"emacs-nox-24.3-20.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"emacs-terminal-24.3-20.el7_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs / emacs-common / emacs-el / emacs-filesystem / emacs-nox / etc");
}
