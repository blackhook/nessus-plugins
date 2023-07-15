#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2492 and 
# CentOS Errata and Security Advisory 2017:2492 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102881);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2017-1000061");
  script_xref(name:"RHSA", value:"2017:2492");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"CentOS 7 : xmlsec1 (CESA-2017:2492)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
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
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004693.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82354f20");
  script_set_attribute(attribute:"solution", value:
"Update the affected xmlsec1 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1000061");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xmlsec1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xmlsec1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xmlsec1-gcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xmlsec1-gcrypt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xmlsec1-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xmlsec1-gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xmlsec1-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xmlsec1-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xmlsec1-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xmlsec1-openssl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xmlsec1-1.2.20-7.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xmlsec1-devel-1.2.20-7.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xmlsec1-gcrypt-1.2.20-7.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xmlsec1-gcrypt-devel-1.2.20-7.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xmlsec1-gnutls-1.2.20-7.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xmlsec1-gnutls-devel-1.2.20-7.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xmlsec1-nss-1.2.20-7.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xmlsec1-nss-devel-1.2.20-7.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xmlsec1-openssl-1.2.20-7.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xmlsec1-openssl-devel-1.2.20-7.el7_4")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xmlsec1 / xmlsec1-devel / xmlsec1-gcrypt / xmlsec1-gcrypt-devel / etc");
}
