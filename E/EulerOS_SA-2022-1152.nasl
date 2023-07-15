#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157953);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/12");

  script_cve_id("CVE-2021-37600");

  script_name(english:"EulerOS Virtualization 3.0.6.6 : util-linux (EulerOS-SA-2022-1152)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the util-linux packages installed, the EulerOS Virtualization installation on the remote
host is affected by the following vulnerabilities :

  - ** DISPUTED ** An integer overflow in util-linux through 2.37.1 can potentially cause a buffer overflow if
    an attacker were able to use system resources in a way that leads to a large number in the
    /proc/sysvipc/sem file. NOTE: this is unexploitable in GNU C Library environments, and possibly in all
    realistic environments. (CVE-2021-37600)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1152
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40392682");
  script_set_attribute(attribute:"solution", value:
"Update the affected util-linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37600");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libblkid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libblkid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libmount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libuuid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libuuid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:uuidd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.6.6") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.6");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "libblkid-2.23.2-52.1.h12.eulerosv2r7",
  "libblkid-devel-2.23.2-52.1.h12.eulerosv2r7",
  "libmount-2.23.2-52.1.h12.eulerosv2r7",
  "libuuid-2.23.2-52.1.h12.eulerosv2r7",
  "libuuid-devel-2.23.2-52.1.h12.eulerosv2r7",
  "util-linux-2.23.2-52.1.h12.eulerosv2r7",
  "uuidd-2.23.2-52.1.h12.eulerosv2r7"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "util-linux");
}
