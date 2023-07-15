#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2789 and 
# CentOS Errata and Security Advisory 2017:2789 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103385);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-12150", "CVE-2017-12163", "CVE-2017-2619");
  script_xref(name:"RHSA", value:"2017:2789");

  script_name(english:"CentOS 6 : samba (CESA-2017:2789)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for samba is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) protocol and the related Common Internet File System (CIFS)
protocol, which allow PC-compatible machines to share files, printers,
and various information.

Security Fix(es) :

* A race condition was found in samba server. A malicious samba client
could use this flaw to access files and directories in areas of the
server file system not exported under the share definitions.
(CVE-2017-2619)

* It was found that samba did not enforce 'SMB signing' when certain
configuration options were enabled. A remote attacker could launch a
man-in-the-middle attack and retrieve information in plain-text.
(CVE-2017-12150)

* An information leak flaw was found in the way SMB1 protocol was
implemented by Samba. A malicious client could use this flaw to dump
server memory contents to a file on the samba share or to a shared
printer, though the exact area of server memory cannot be controlled
by the attacker. (CVE-2017-12163)

Red Hat would like to thank the Samba project for reporting
CVE-2017-2619 and CVE-2017-12150 and Yihan Lian and Zhibin Hu (Qihoo
360 GearTeam), Stefan Metzmacher (SerNet), and Jeremy Allison (Google)
for reporting CVE-2017-12163. Upstream acknowledges Jann Horn (Google)
as the original reporter of CVE-2017-2619; and Stefan Metzmacher
(SerNet) as the original reporter of CVE-2017-12150."
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-September/022543.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d702526"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-2619");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-6", reference:"libsmbclient-3.6.23-45.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsmbclient-devel-3.6.23-45.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-3.6.23-45.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-client-3.6.23-45.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-common-3.6.23-45.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-doc-3.6.23-45.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-domainjoin-gui-3.6.23-45.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"samba-glusterfs-3.6.23-45.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-swat-3.6.23-45.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-winbind-3.6.23-45.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-winbind-clients-3.6.23-45.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-winbind-devel-3.6.23-45.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-winbind-krb5-locator-3.6.23-45.el6_9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsmbclient / libsmbclient-devel / samba / samba-client / etc");
}
