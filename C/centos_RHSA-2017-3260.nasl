#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:3260 and 
# CentOS Errata and Security Advisory 2017:3260 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104789);
  script_version("3.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-14746", "CVE-2017-15275");
  script_xref(name:"RHSA", value:"2017:3260");

  script_name(english:"CentOS 7 : samba (CESA-2017:3260)");
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
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) protocol and the related Common Internet File System (CIFS)
protocol, which allow PC-compatible machines to share files, printers,
and various information.

Security Fix(es) :

* A use-after-free flaw was found in the way samba servers handled
certain SMB1 requests. An unauthenticated attacker could send
specially crafted SMB1 requests to cause the server to crash or
execute arbitrary code. (CVE-2017-14746)

* A memory disclosure flaw was found in samba. An attacker could
retrieve parts of server memory, which could contain potentially
sensitive data, by sending specially crafted requests to the samba
server. (CVE-2017-15275)

Red Hat would like to thank the Samba project for reporting these
issues. Upstream acknowledges Yihan Lian and Zhibin Hu (Qihoo 360
GearTeam) as the original reporter of CVE-2017-14746; and Volker
Lendecke (SerNet and the Samba Team) as the original reporter of
CVE-2017-15275."
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-November/022631.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?346a1ef5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14746");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/28");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ctdb-4.6.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ctdb-tests-4.6.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libsmbclient-4.6.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libsmbclient-devel-4.6.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libwbclient-4.6.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libwbclient-devel-4.6.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-4.6.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-client-4.6.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-client-libs-4.6.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-common-4.6.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-common-libs-4.6.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-common-tools-4.6.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-dc-4.6.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-dc-libs-4.6.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-devel-4.6.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-krb5-printing-4.6.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-libs-4.6.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-pidl-4.6.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-python-4.6.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-test-4.6.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-test-libs-4.6.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-vfs-glusterfs-4.6.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-winbind-4.6.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-winbind-clients-4.6.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-winbind-krb5-locator-4.6.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"samba-winbind-modules-4.6.2-12.el7_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ctdb / ctdb-tests / libsmbclient / libsmbclient-devel / libwbclient / etc");
}
