#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2757 and 
# CentOS Errata and Security Advisory 2018:2757 respectively.
#

include('compat.inc');

if (description)
{
  script_id(117830);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/24");

  script_cve_id(
    "CVE-2018-10850",
    "CVE-2018-10935",
    "CVE-2018-14624",
    "CVE-2018-14638"
  );
  script_xref(name:"RHSA", value:"2018:2757");

  script_name(english:"CentOS 7 : 389-ds-base (CESA-2018:2757)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for 389-ds-base is now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

389 Directory Server is an LDAP version 3 (LDAPv3) compliant server.
The base packages include the Lightweight Directory Access Protocol
(LDAP) server and command-line utilities for server administration.

Security Fix(es) :

* 389-ds-base: race condition on reference counter leads to DoS using
persistent search (CVE-2018-10850)

* 389-ds-base: ldapsearch with server side sort allows users to cause
a crash (CVE-2018-10935)

* 389-ds-base: Server crash through modify command with large DN
(CVE-2018-14624)

* 389-ds-base: Crash in delete_passwdPolicy when persistent search
connections are terminated unexpectedly (CVE-2018-14638)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

The CVE-2018-10850 issue was discovered by Thierry Bordaz (Red Hat)
and the CVE-2018-14638 issue was discovered by Viktor Ashirov (Red
Hat).

Bug Fix(es) :

* Previously, the nucn-stans framework was enabled by default in
Directory Server, but the framework is not stable. As a consequence,
deadlocks and file descriptor leaks could occur. This update changes
the default value of the nsslapd-enable-nunc-stans parameter to 'off'.
As a result, Directory Server is now stable. (BZ#1614836)

* When a search evaluates the 'shadowAccount' entry, Directory Server
adds the shadow attributes to the entry. If the fine-grained password
policy is enabled, the 'shadowAccount' entry can contain its own
'pwdpolicysubentry' policy attribute. Previously, to retrieve this
attribute, the server started an internal search for each
'shadowAccount' entry, which was unnecessary because the entry was
already known to the server. With this update, Directory Server only
starts internal searches if the entry is not known. As a result, the
performance of searches, such as response time and throughput, is
improved. (BZ#1615924)");
  # https://lists.centos.org/pipermail/centos-announce/2018-September/023042.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48499d25");
  script_set_attribute(attribute:"solution", value:
"Update the affected 389-ds-base packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10850");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"389-ds-base-1.3.7.5-28.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"389-ds-base-devel-1.3.7.5-28.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"389-ds-base-libs-1.3.7.5-28.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"389-ds-base-snmp-1.3.7.5-28.el7_5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds-base / 389-ds-base-devel / 389-ds-base-libs / etc");
}
