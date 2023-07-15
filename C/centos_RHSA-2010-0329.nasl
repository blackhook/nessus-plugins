#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0329 and 
# CentOS Errata and Security Advisory 2010:0329 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(45442);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-0734");
  script_bugtraq_id(38162);
  script_xref(name:"RHSA", value:"2010:0329");

  script_name(english:"CentOS 3 / 4 : curl (CESA-2010:0329)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated curl packages that fix one security issue are now available
for Red Hat Enterprise Linux 3 and 4.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

cURL is a tool for getting files from FTP, HTTP, Gopher, Telnet, and
DICT servers, using any of the supported protocols. cURL is designed
to work without user interaction or any kind of interactivity.

Wesley Miaw discovered that when deflate compression was used, libcurl
could call the registered write callback function with data exceeding
the documented limit. A malicious server could use this flaw to crash
an application using libcurl or, potentially, execute arbitrary code.
Note: This issue only affected applications using libcurl that rely on
the documented data size limit, and that copy the data to the
insufficiently sized buffer. (CVE-2010-0734)

Users of curl should upgrade to these updated packages, which contain
a backported patch to correct this issue. All running applications
using libcurl must be restarted for the update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-April/016615.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a846d0fd"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-April/016616.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b3a39ea"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-April/016619.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?88d46e04"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-April/016620.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61c0ee74"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:curl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/09");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"curl-7.10.6-11.rhel3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"curl-7.10.6-11.rhel3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"curl-devel-7.10.6-11.rhel3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"curl-devel-7.10.6-11.rhel3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"curl-7.12.1-11.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"curl-7.12.1-11.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"curl-devel-7.12.1-11.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"curl-devel-7.12.1-11.1.el4_8.3")) flag++;


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
