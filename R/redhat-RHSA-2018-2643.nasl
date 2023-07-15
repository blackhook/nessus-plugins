#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2643. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(117324);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-1000180",
    "CVE-2018-10237",
    "CVE-2018-1067",
    "CVE-2018-10862",
    "CVE-2018-10915",
    "CVE-2018-1114",
    "CVE-2018-8039"
  );
  script_xref(name:"RHSA", value:"2018:2643");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 7 : Virtualization (RHSA-2018:2643)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for rhvm-appliance is now available for Red Hat
Virtualization 4 for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The RHV-M Virtual Appliance automates the process of installing and
configuring the Red Hat Virtualization Manager. The appliance is
available to download as an OVA file from the Customer Portal.

The following packages have been upgraded to a later upstream version:
rhvm-appliance (4.2). (BZ#1590658, BZ#1591095, BZ#1591096, BZ#1592655,
BZ# 1594636, BZ#1597534, BZ#1612683)

Red Hat would like to thank the PostgreSQL project for reporting
CVE-2018-10915 and Ammarit Thongthua (Deloitte Thailand Pentest team)
and Nattakit Intarasorn (Deloitte Thailand Pentest team) for reporting
CVE-2018-1067. Upstream acknowledges Andrew Krasichkov as the original
reporter of CVE-2018-10915.

Security fixes :

* vulnerability: wildfly-core: Path traversal can allow the extraction
of .war archives to write arbitrary files (Zip Slip) (CVE-2018-10862)

* vulnerability: apache-cxf: TLS hostname verification does not work
correctly with com.sun.net.ssl.* (CVE-2018-8039)

* vulnerability: postgresql: Certain host connection parameters defeat
client-side security defenses (CVE-2018-10915)

* vulnerability: undertow: HTTP header injection using CRLF with UTF-8
Encoding (incomplete fix of ) (CVE-2018-1067, CVE-2016-4993)

* vulnerability: undertow: File descriptor leak caused by
JarURLConnection.getLastModified() allows attacker to cause a denial
of service (CVE-2018-1114)

* vulnerability: guava: Unbounded memory allocation in
AtomicDoubleArray and CompoundOrdering classes allow remote attackers
to cause a denial of service (CVE-2018-10237)

* vulnerability: bouncycastle: flaw in the low-level interface to RSA
key pair generator (CVE-2018-1000180)

For more details about the security issues, including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE pages listed in the References section.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:2643");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-1067");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-1114");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-8039");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-10237");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-10862");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-10915");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-1000180");
  script_set_attribute(attribute:"solution", value:
"Update the affected rhvm-appliance package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhvm-appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:2643";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;

  if (! (rpm_exists(release:"RHEL7", rpm:"rhvm-appliance-4.2"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Virtualization");

  if (rpm_check(release:"RHEL7", reference:"rhvm-appliance-4.2-20180828.0.el7")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rhvm-appliance");
  }
}
