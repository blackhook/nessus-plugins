#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118432);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/03");

  script_cve_id("CVE-2014-9402", "CVE-2016-3075", "CVE-2018-11236");
  script_bugtraq_id(71670);

  script_name(english:"EulerOS Virtualization 2.5.0 : glibc (EulerOS-SA-2018-1344)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the glibc packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - The nss_dns implementation of getnetbyname in GNU C
    Library (aka glibc) before 2.21, when the DNS backend
    in the Name Service Switch configuration is enabled,
    allows remote attackers to cause a denial of service
    (infinite loop) by sending a positive answer while a
    network name is being process.(CVE-2014-9402)

  - A stack overflow vulnerability was found in
    _nss_dns_getnetbyname_r.On systems with nsswitch
    configured to include 'networks: dns' with a privileged
    or network-facing service that would attempt to resolve
    user-provided network names, an attacker could provide
    an excessively long network name, resulting in stack
    corruption and code execution.(CVE-2016-3075)

  - stdlib/canonicalize.c in the GNU C Library (aka glibc
    or libc6) 2.27 and earlier, when processing very long
    pathname arguments to the realpath function, could
    encounter an integer overflow on 32-bit architectures,
    leading to a stack-based buffer overflow and,
    potentially, arbitrary code execution.(CVE-2018-11236)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1344
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?150706e2");
  script_set_attribute(attribute:"solution", value:
"Update the affected glibc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11236");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.5.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.5.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.5.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["glibc-2.17-111.h12",
        "glibc-common-2.17-111.h12",
        "glibc-devel-2.17-111.h12",
        "glibc-headers-2.17-111.h12",
        "nscd-2.17-111.h12"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
