#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0849 and 
# CentOS Errata and Security Advisory 2008:0849 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(34052);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-3651", "CVE-2008-3652");
  script_bugtraq_id(30657);
  script_xref(name:"RHSA", value:"2008:0849");

  script_name(english:"CentOS 3 / 4 / 5 : ipsec-tools (CESA-2008:0849)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated ipsec-tools package that fixes two security issues is now
available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The ipsec-tools package is used in conjunction with the IPsec
functionality in the Linux kernel and includes racoon, an IKEv1 keying
daemon.

Two denial of service flaws were found in the ipsec-tools racoon
daemon. It was possible for a remote attacker to cause the racoon
daemon to consume all available memory. (CVE-2008-3651, CVE-2008-3652)

Users of ipsec-tools should upgrade to this updated package, which
contains backported patches that resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-August/015207.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e4b11509"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-August/015208.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2890dc0b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-August/015215.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef83d500"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-August/015216.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?564c72e3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-August/015222.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2689bae7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-August/015224.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?11be8708"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ipsec-tools package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipsec-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"ipsec-tools-0.2.5-0.7.rhel3.5")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ipsec-tools-0.3.3-7.c4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"ipsec-tools-0.6.5-9.el5_2.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipsec-tools");
}
