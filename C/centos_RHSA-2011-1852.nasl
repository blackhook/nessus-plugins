#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1852 and 
# CentOS Errata and Security Advisory 2011:1852 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(57406);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-4862");
  script_xref(name:"RHSA", value:"2011:1852");

  script_name(english:"CentOS 6 : krb5-appl (CESA-2011:1852)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5-appl packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
Critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The krb5-appl packages provide Kerberos-aware telnet, ftp, rcp, rsh,
and rlogin clients and servers. Kerberos is a network authentication
system which allows clients and servers to authenticate to each other
using symmetric encryption and a trusted third-party, the Key
Distribution Center (KDC).

A buffer overflow flaw was found in the MIT krb5 telnet daemon
(telnetd). A remote attacker who can access the telnet port of a
target machine could use this flaw to execute arbitrary code as root.
(CVE-2011-4862)

Note that the krb5 telnet daemon is not enabled by default in any
version of Red Hat Enterprise Linux. In addition, the default firewall
rules block remote access to the telnet port. This flaw does not
affect the telnet daemon distributed in the telnet-server package.

For users who have installed the krb5-appl-servers package, have
enabled the krb5 telnet daemon, and have it accessible remotely, this
update should be applied immediately.

All krb5-appl-server users should upgrade to these updated packages,
which contain a backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-December/018361.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?978d146e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected krb5-appl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-760");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux BSD-derived Telnet Service Encryption Key ID Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-appl-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-appl-servers");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/28");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"krb5-appl-clients-1.0.1-7.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"krb5-appl-servers-1.0.1-7.el6_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-appl-clients / krb5-appl-servers");
}
