#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1265 and 
# CentOS Errata and Security Advisory 2017:1265 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100329);
  script_version("3.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-2125", "CVE-2016-2126", "CVE-2017-2619");
  script_xref(name:"RHSA", value:"2017:1265");

  script_name(english:"CentOS 7 : samba (CESA-2017:1265)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for samba is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) protocol and the related Common Internet File System (CIFS)
protocol, which allow PC-compatible machines to share files, printers,
and various information.

Security Fix(es) :

* It was found that Samba always requested forwardable tickets when
using Kerberos authentication. A service to which Samba authenticated
using Kerberos could subsequently use the ticket to impersonate Samba
to other services or domain users. (CVE-2016-2125)

* A flaw was found in the way Samba handled PAC (Privilege Attribute
Certificate) checksums. A remote, authenticated attacker could use
this flaw to crash the winbindd process. (CVE-2016-2126)

* A race condition was found in samba server. A malicious samba client
could use this flaw to access files and directories, in areas of the
server file system not exported under the share definitions.
(CVE-2017-2619)

Red Hat would like to thank the Samba project for reporting
CVE-2017-2619. Upstream acknowledges Jann Horn (Google) as the
original reporter of CVE-2017-2619."
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-May/022412.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a0389580"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ctdb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-krb5-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-vfs-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/23");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ctdb-4.4.4-13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ctdb-tests-4.4.4-13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libsmbclient-4.4.4-13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libsmbclient-devel-4.4.4-13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libwbclient-4.4.4-13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libwbclient-devel-4.4.4-13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-4.4.4-13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-client-4.4.4-13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-client-libs-4.4.4-13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-common-4.4.4-13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-common-libs-4.4.4-13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-common-tools-4.4.4-13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-dc-4.4.4-13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-dc-libs-4.4.4-13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-devel-4.4.4-13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-krb5-printing-4.4.4-13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-libs-4.4.4-13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-pidl-4.4.4-13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-python-4.4.4-13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-test-4.4.4-13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-test-libs-4.4.4-13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-vfs-glusterfs-4.4.4-13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-winbind-4.4.4-13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-winbind-clients-4.4.4-13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-winbind-krb5-locator-4.4.4-13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-winbind-modules-4.4.4-13.el7_3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ctdb / ctdb-tests / libsmbclient / libsmbclient-devel / libwbclient / etc");
}
