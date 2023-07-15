#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1700 and 
# CentOS Errata and Security Advisory 2015:1700 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86502);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-5189", "CVE-2015-5190");
  script_xref(name:"RHSA", value:"2015:1700");

  script_name(english:"CentOS 6 / 7 : pcs (CESA-2015:1700)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pcs packages that fix two security issues are now available
for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The pcs packages provide a command-line configuration system for the
Pacemaker and Corosync utilities.

A command injection flaw was found in the pcsd web UI. An attacker
able to trick a victim that was logged in to the pcsd web UI into
visiting a specially crafted URL could use this flaw to execute
arbitrary code with root privileges on the server hosting the web UI.
(CVE-2015-5190)

A race condition was found in the way the pcsd web UI backend
performed authorization of user requests. An attacker could use this
flaw to send a request that would be evaluated as originating from a
different user, potentially allowing the attacker to perform actions
with permissions of a more privileged user. (CVE-2015-5189)

These issues were discovered by Tomas Jelinek of Red Hat.

All pcs users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-September/021356.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?19e3982b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-September/021363.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e72fba9d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pcs packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5190");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-clufter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-6", reference:"pcs-0.9.139-9.el6_7.1")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pcs-0.9.137-13.el7_1.4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-clufter-0.9.137-13.el7_1.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pcs / python-clufter");
}
