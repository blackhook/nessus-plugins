#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156312);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/15");

  script_cve_id("CVE-2021-3660");

  script_name(english:"EulerOS 2.0 SP8 : cockpit (EulerOS-SA-2021-2797)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the cockpit packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - Cockpit (and its plugins) do not seem to protect itself against clickjacking. It is possible to render a
    page from a cockpit server via another website, inside an <iFrame> HTML entry. This may be used by a
    malicious website in clickjacking or similar attacks. (CVE-2021-3660)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2797
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e448415");
  script_set_attribute(attribute:"solution", value:
"Update the affected cockpit packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3660");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:cockpit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:cockpit-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:cockpit-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:cockpit-packagekit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:cockpit-storaged");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:cockpit-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:cockpit-ws");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "cockpit-178-1.h2.eulerosv2r8",
  "cockpit-bridge-178-1.h2.eulerosv2r8",
  "cockpit-doc-178-1.h2.eulerosv2r8",
  "cockpit-packagekit-178-1.h2.eulerosv2r8",
  "cockpit-storaged-178-1.h2.eulerosv2r8",
  "cockpit-system-178-1.h2.eulerosv2r8",
  "cockpit-ws-178-1.h2.eulerosv2r8"
];

foreach (var pkg in pkgs)
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cockpit");
}
