#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0771 and 
# CentOS Errata and Security Advisory 2013:0771 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(66206);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-1944");
  script_bugtraq_id(59058);
  script_xref(name:"RHSA", value:"2013:0771");

  script_name(english:"CentOS 5 / 6 : curl (CESA-2013:0771)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated curl packages that fix one security issue are now available
for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

cURL provides the libcurl library and a command line tool for
downloading files from servers using various protocols, including
HTTP, FTP, and LDAP.

A flaw was found in the way libcurl matched domains associated with
cookies. This could lead to cURL or an application linked against
libcurl sending the wrong cookie if only part of the domain name
matched the domain associated with the cookie, disclosing the cookie
to unrelated hosts. (CVE-2013-1944)

Red Hat would like to thank the cURL project for reporting this issue.
Upstream acknowledges YAMADA Yasuharu as the original reporter.

Users of curl should upgrade to these updated packages, which contain
a backported patch to correct this issue. All running applications
using libcurl must be restarted for the update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-April/019702.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9fe8e202"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-April/019704.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ae31aa5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-1944");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:curl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/25");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x / 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"curl-7.15.5-16.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"curl-devel-7.15.5-16.el5_9")) flag++;

if (rpm_check(release:"CentOS-6", reference:"curl-7.19.7-36.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libcurl-7.19.7-36.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libcurl-devel-7.19.7-36.el6_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / curl-devel / libcurl / libcurl-devel");
}
