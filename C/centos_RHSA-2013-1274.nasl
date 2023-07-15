#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1274 and 
# CentOS Errata and Security Advisory 2013:1274 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(70001);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-4325");
  script_bugtraq_id(62499);
  script_xref(name:"RHSA", value:"2013:1274");

  script_name(english:"CentOS 6 : hplip (CESA-2013:1274)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated hplip packages that fix one security issue are now available
for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The hplip packages contain the Hewlett-Packard Linux Imaging and
Printing Project (HPLIP), which provides drivers for Hewlett-Packard
printers and multi-function peripherals.

HPLIP communicated with PolicyKit for authorization via a D-Bus API
that is vulnerable to a race condition. This could lead to intended
PolicyKit authorizations being bypassed. This update modifies HPLIP to
communicate with PolicyKit via a different API that is not vulnerable
to the race condition. (CVE-2013-4325)

All users of hplip are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-September/019947.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a243432e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected hplip packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4325");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hpijs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hplip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hplip-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hplip-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hplip-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsane-hpaio");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-6", reference:"hpijs-3.12.4-4.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"hplip-3.12.4-4.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"hplip-common-3.12.4-4.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"hplip-gui-3.12.4-4.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"hplip-libs-3.12.4-4.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsane-hpaio-3.12.4-4.el6_4.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hpijs / hplip / hplip-common / hplip-gui / hplip-libs / etc");
}
