#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0918 and 
# CentOS Errata and Security Advisory 2011:0918 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(55515);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-2192");
  script_bugtraq_id(48434);
  script_xref(name:"RHSA", value:"2011:0918");

  script_name(english:"CentOS 4 / 5 : curl (CESA-2011:0918)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated curl packages that fix one security issue are now available
for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

cURL provides the libcurl library and a command line tool for
downloading files from servers using various protocols, including
HTTP, FTP, and LDAP.

It was found that cURL always performed credential delegation when
authenticating with GSSAPI. A rogue server could use this flaw to
obtain the client's credentials and impersonate that client to other
servers that are using GSSAPI. (CVE-2011-2192)

Users of curl should upgrade to these updated packages, which contain
a backported patch to correct this issue. All running applications
using libcurl must be restarted for the update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-August/017669.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e0125226"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-August/017670.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9bd496c4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-July/017641.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d738b6a8"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-July/017642.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?28ddfee8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:curl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"curl-7.12.1-17.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"curl-7.12.1-17.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"curl-devel-7.12.1-17.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"curl-devel-7.12.1-17.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"curl-7.15.5-9.el5_6.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"curl-devel-7.15.5-9.el5_6.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / curl-devel");
}
