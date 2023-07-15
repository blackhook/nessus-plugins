#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0565 and 
# CentOS Errata and Security Advisory 2010:0565 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(47867);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-2074");
  script_bugtraq_id(40837);
  script_xref(name:"RHSA", value:"2010:0565");

  script_name(english:"CentOS 5 : w3m (CESA-2010:0565)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated w3m packages that fix one security issue are now available for
Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The w3m program is a pager (or text file viewer) that can also be used
as a text mode web browser.

It was discovered that w3m is affected by the previously published
'null prefix attack', caused by incorrect handling of NULL characters
in X.509 certificates. If an attacker is able to get a
carefully-crafted certificate signed by a trusted Certificate
Authority, the attacker could use the certificate during a
man-in-the-middle attack and potentially confuse w3m into accepting it
by mistake. (CVE-2010-2074)

All w3m users should upgrade to these updated packages, which contain
a backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-July/016837.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?672ae64b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-July/016838.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a94531b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected w3m packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:w3m");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:w3m-img");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"w3m-0.5.1-17.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"w3m-img-0.5.1-17.el5_5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "w3m / w3m-img");
}
