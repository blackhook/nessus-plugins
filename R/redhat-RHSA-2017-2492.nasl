#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2492. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(102634);
  script_version("3.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2017-1000061");
  script_xref(name:"RHSA", value:"2017:2492");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 7 : xmlsec1 (RHSA-2017:2492)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for xmlsec1 is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

XML Security Library is a C library based on LibXML2 and OpenSSL. The
library was created with a goal to support major XML security
standards 'XML Digital Signature' and 'XML Encryption'.

Security Fix(es) :

* It was discovered xmlsec1's use of libxml2 inadvertently enabled
external entity expansion (XXE) along with validation. An attacker
could craft an XML file that would cause xmlsec1 to try and read local
files or HTTP/FTP URLs, leading to information disclosure or denial of
service. (CVE-2017-1000061)");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017:2492");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2017-1000061");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xmlsec1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xmlsec1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xmlsec1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xmlsec1-gcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xmlsec1-gcrypt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xmlsec1-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xmlsec1-gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xmlsec1-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xmlsec1-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xmlsec1-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xmlsec1-openssl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  rhsa = "RHSA-2017:2492";
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
  if (rpm_check(release:"RHEL7", reference:"xmlsec1-1.2.20-7.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", reference:"xmlsec1-debuginfo-1.2.20-7.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", reference:"xmlsec1-devel-1.2.20-7.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", reference:"xmlsec1-gcrypt-1.2.20-7.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", reference:"xmlsec1-gcrypt-devel-1.2.20-7.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", reference:"xmlsec1-gnutls-1.2.20-7.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", reference:"xmlsec1-gnutls-devel-1.2.20-7.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", reference:"xmlsec1-nss-1.2.20-7.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", reference:"xmlsec1-nss-devel-1.2.20-7.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", reference:"xmlsec1-openssl-1.2.20-7.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", reference:"xmlsec1-openssl-devel-1.2.20-7.el7_4")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xmlsec1 / xmlsec1-debuginfo / xmlsec1-devel / xmlsec1-gcrypt / etc");
  }
}
