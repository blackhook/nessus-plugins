#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0807 and 
# CentOS Errata and Security Advisory 2013:0807 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(66396);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-5532");
  script_bugtraq_id(56710);
  script_xref(name:"RHSA", value:"2013:0807");

  script_name(english:"CentOS 5 : hypervkvpd (CESA-2013:0807)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated hypervkvpd package that fixes one security issue and one
bug is now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The hypervkvpd package contains hypervkvpd, the guest Microsoft
Hyper-V Key-Value Pair (KVP) daemon. The daemon passes basic
information to the host through VMBus, such as the guest IP address,
fully qualified domain name, operating system name, and operating
system release number.

A denial of service flaw was found in the way hypervkvpd processed
certain Netlink messages. A local, unprivileged user in a guest
(running on Microsoft Hyper-V) could send a Netlink message that, when
processed, would cause the guest's hypervkvpd daemon to exit.
(CVE-2012-5532)

The CVE-2012-5532 issue was discovered by Florian Weimer of the Red
Hat Product Security Team.

This update also fixes the following bug :

* The hypervkvpd daemon did not close the file descriptors for pool
files when they were updated. This could eventually lead to hypervkvpd
crashing with a 'KVP: Failed to open file, pool: 1' error after
consuming all available file descriptors. With this update, the file
descriptors are closed, correcting this issue. (BZ#953502)

Users of hypervkvpd are advised to upgrade to this updated package,
which contains backported patches to correct these issues. After
installing the update, it is recommended to reboot all guest machines."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-May/019717.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5cc49740"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected hypervkvpd package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5532");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hypervkvpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/14");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"hypervkvpd-0-0.7.el5_9.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hypervkvpd");
}
