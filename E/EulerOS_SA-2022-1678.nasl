##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160707);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2021-3999",
    "CVE-2021-43396",
    "CVE-2022-23218",
    "CVE-2022-23219"
  );

  script_name(english:"EulerOS Virtualization 3.0.2.0 : glibc (EulerOS-SA-2022-1678)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the glibc packages installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - The deprecated compatibility function clnt_create in the sunrpc module of the GNU C Library (aka glibc)
    through 2.34 copies its hostname argument on the stack without validating its length, which may result in
    a buffer overflow, potentially resulting in a denial of service or (if an application is not built with a
    stack protector enabled) arbitrary code execution. (CVE-2022-23219)

  - A flaw was found in glibc. An off-by-one buffer overflow and underflow in getcwd() may lead to memory
    corruption when the size of the buffer is exactly 1. A local attacker who can control the input buffer and
    size passed to getcwd() in a setuid program could use this flaw to potentially execute arbitrary code and
    escalate their privileges on the system. (CVE-2021-3999)

  - ** DISPUTED ** In iconvdata/iso-2022-jp-3.c in the GNU C Library (aka glibc) 2.34, remote attackers can
    force iconv() to emit a spurious '\0' character via crafted ISO-2022-JP-3 data that is accompanied by an
    internal state reset. This may affect data integrity in certain iconv() use cases. NOTE: the vendor states
    the bug cannot be invoked through user input and requires iconv to be invoked with a NULL inbuf, which
    ought to require a separate application bug to do so unintentionally. Hence there's no security impact to
    the bug. (CVE-2021-43396)

  - The deprecated compatibility function svcunix_create in the sunrpc module of the GNU C Library (aka glibc)
    through 2.34 copies its path argument on the stack without validating its length, which may result in a
    buffer overflow, potentially resulting in a denial of service or (if an application is not built with a
    stack protector enabled) arbitrary code execution. (CVE-2022-23218)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1678
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6614dd85");
  script_set_attribute(attribute:"solution", value:
"Update the affected glibc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23219");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-all-langpacks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libnsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "glibc-2.28-9.h70",
  "glibc-all-langpacks-2.28-9.h70",
  "glibc-common-2.28-9.h70",
  "glibc-devel-2.28-9.h70",
  "glibc-headers-2.28-9.h70",
  "libnsl-2.28-9.h70",
  "nscd-2.28-9.h70"
];

foreach (var pkg in pkgs)
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
