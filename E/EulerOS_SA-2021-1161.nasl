#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(145743);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/04");

  script_cve_id(
    "CVE-2020-29361",
    "CVE-2020-29362",
    "CVE-2020-29363"
  );

  script_name(english:"EulerOS 2.0 SP8 : p11-kit (EulerOS-SA-2021-1161)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the p11-kit packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - An issue was discovered in p11-kit 0.21.1 through
    0.23.21. Multiple integer overflows have been
    discovered in the array allocations in the p11-kit
    library and the p11-kit list command, where overflow
    checks are missing before calling realloc or
    calloc.(CVE-2020-29361)

  - An issue was discovered in p11-kit 0.21.1 through
    0.23.21. A heap-based buffer over-read has been
    discovered in the RPC protocol used by thep11-kit
    server/remote commands and the client library. When the
    remote entity supplies a byte array through a
    serialized PKCS#11 function call, the receiving entity
    may allow the reading of up to 4 bytes of memory past
    the heap allocation.(CVE-2020-29362)

  - An issue was discovered in p11-kit 0.23.6 through
    0.23.21. A heap-based buffer overflow has been
    discovered in the RPC protocol used by p11-kit
    server/remote commands and the client library. When the
    remote entity supplies a serialized byte array in a
    CK_ATTRIBUTE, the receiving entity may not allocate
    sufficient length for the buffer to store the
    deserialized value.(CVE-2020-29363)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1161
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b63e0cdc");
  script_set_attribute(attribute:"solution", value:
"Update the affected p11-kit packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-29362");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:p11-kit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:p11-kit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:p11-kit-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:p11-kit-trust");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["p11-kit-0.23.14-1.h2.eulerosv2r8",
        "p11-kit-devel-0.23.14-1.h2.eulerosv2r8",
        "p11-kit-server-0.23.14-1.h2.eulerosv2r8",
        "p11-kit-trust-0.23.14-1.h2.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "p11-kit");
}
