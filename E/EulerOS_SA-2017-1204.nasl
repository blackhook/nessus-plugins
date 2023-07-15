#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103062);
  script_version("3.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2016-7444",
    "CVE-2017-5334",
    "CVE-2017-5335",
    "CVE-2017-5336",
    "CVE-2017-5337",
    "CVE-2017-7507"
  );

  script_name(english:"EulerOS 2.0 SP2 : gnutls (EulerOS-SA-2017-1204)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the gnutls packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A double-free flaw was found in the way GnuTLS parsed
    certain X.509 certificates with Proxy Certificate
    Information extension. An attacker could create a
    specially-crafted certificate which, when processed by
    an application compiled against GnuTLS, could cause
    that application to crash. (CVE-2017-5334)

  - Multiple flaws were found in the way gnutls processed
    OpenPGP certificates. An attacker could create
    specially crafted OpenPGP certificates which, when
    parsed by gnutls, would cause it to crash.
    (CVE-2017-5335, CVE-2017-5336, CVE-2017-5337,
    CVE-2017-7869)

  - A null pointer dereference flaw was found in the way
    GnuTLS processed ClientHello messages with
    status_request extension. A remote attacker could use
    this flaw to cause an application compiled with GnuTLS
    to crash. (CVE-2017-7507)

  - A flaw was found in the way GnuTLS validated
    certificates using OCSP responses. This could falsely
    report a certificate as valid under certain
    circumstances. (CVE-2016-7444)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1204
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?087d2021");
  script_set_attribute(attribute:"solution", value:
"Update the affected gnutls packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gnutls-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gnutls-dane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gnutls-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["gnutls-3.3.26-9",
        "gnutls-c++-3.3.26-9",
        "gnutls-dane-3.3.26-9",
        "gnutls-devel-3.3.26-9",
        "gnutls-utils-3.3.26-9"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls");
}
