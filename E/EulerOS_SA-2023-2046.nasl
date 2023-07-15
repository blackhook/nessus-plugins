#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176862);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/07");

  script_cve_id("CVE-2022-41973", "CVE-2022-41974");

  script_name(english:"EulerOS Virtualization 2.11.1 : multipath-tools (EulerOS-SA-2023-2046)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the multipath-tools packages installed, the EulerOS Virtualization installation on the
remote host is affected by the following vulnerabilities :

  - multipath-tools 0.7.7 through 0.9.x before 0.9.2 allows local users to obtain root access, as exploited in
    conjunction with CVE-2022-41974. Local users able to access /dev/shm can change symlinks in multipathd due
    to incorrect symlink handling, which could lead to controlled file writes outside of the /dev/shm
    directory. This could be used indirectly for local privilege escalation to root. (CVE-2022-41973)

  - multipath-tools 0.7.0 through 0.9.x before 0.9.2 allows local users to obtain root access, as exploited
    alone or in conjunction with CVE-2022-41973. Local users able to write to UNIX domain sockets can bypass
    access controls and manipulate the multipath setup. This can lead to local privilege escalation to root.
    This occurs because an attacker can repeat a keyword, which is mishandled because arithmetic ADD is used
    instead of bitwise OR. (CVE-2022-41974)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2046
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dbd71b9f");
  script_set_attribute(attribute:"solution", value:
"Update the affected multipath-tools packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41974");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kpartx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:multipath-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.11.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.11.1") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.11.1");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "kpartx-0.8.7-2.h6.eulerosv2r11",
  "multipath-tools-0.8.7-2.h6.eulerosv2r11"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "multipath-tools");
}
