#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:3157 and 
# Oracle Linux Security Advisory ELSA-2018-3157 respectively.
#

include("compat.inc");

if (description)
{
  script_id(118775);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/14");

  script_cve_id("CVE-2018-1000007", "CVE-2018-1000120", "CVE-2018-1000121", "CVE-2018-1000122", "CVE-2018-1000301");
  script_xref(name:"RHSA", value:"2018:3157");

  script_name(english:"Oracle Linux 7 : curl / nss-pem (ELSA-2018-3157)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"From Red Hat Security Advisory 2018:3157 :

An update for curl and nss-pem is now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The curl packages provide the libcurl library and the curl utility for
downloading files from servers using various protocols, including
HTTP, FTP, and LDAP.

The nss-pem package provides the PEM file reader for Network Security
Services (NSS) implemented as a PKCS#11 module.

Security Fix(es) :

* curl: HTTP authentication leak in redirects (CVE-2018-1000007)

* curl: FTP path trickery leads to NIL byte out of bounds write
(CVE-2018-1000120)

* curl: RTSP RTP buffer over-read (CVE-2018-1000122)

* curl: Out-of-bounds heap read when missing RTSP headers allows
information leak of denial of service (CVE-2018-1000301)

* curl: LDAP NULL pointer dereference (CVE-2018-1000121)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank the Curl project for reporting these
issues. Upstream acknowledges Craig de Stigter as the original
reporter of CVE-2018-1000007; Duy Phan Thanh as the original reporter
of CVE-2018-1000120; Max Dymond as the original reporter of
CVE-2018-1000122; the OSS-fuzz project as the original reporter of
CVE-2018-1000301; and Dario Weisser as the original reporter of
CVE-2018-1000121.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.6 Release Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-November/008192.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected curl and / or nss-pem packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-pem");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"curl-7.29.0-51.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libcurl-7.29.0-51.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libcurl-devel-7.29.0-51.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nss-pem-1.0.3-5.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / libcurl / libcurl-devel / nss-pem");
}
