#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(140945);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2016-0801",
    "CVE-2017-0561",
    "CVE-2017-9417"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.6.0 : linux-firmware (EulerOS-SA-2020-1997)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the linux-firmware packages installed,
the EulerOS Virtualization for ARM 64 installation on the remote host
is affected by the following vulnerabilities :

  - Broadcom BCM43xx Wi-Fi chips allow remote attackers to
    execute arbitrary code via unspecified vectors, aka the
    'Broadpwn' issue.(CVE-2017-9417)

  - A remote code execution vulnerability in the Broadcom
    Wi-Fi firmware could enable a remote attacker to
    execute arbitrary code within the context of the Wi-Fi
    SoC. This issue is rated as Critical due to the
    possibility of remote code execution in the context of
    the Wi-Fi SoC. Product: Android. Versions: Kernel-3.10,
    Kernel-3.18. Android ID: A-34199105. References:
    B-RB#110814.(CVE-2017-0561)

  - The Broadcom Wi-Fi driver in the kernel in Android 4.x
    before 4.4.4, 5.x before 5.1.1 LMY49G, and 6.x before
    2016-02-01 allows remote attackers to execute arbitrary
    code or cause a denial of service (memory corruption)
    via crafted wireless control message packets, aka
    internal bug 25662029.(CVE-2016-0801)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1997
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?786f6a02");
  script_set_attribute(attribute:"solution", value:
"Update the affected linux-firmware packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:iwl100-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:iwl1000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:iwl105-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:iwl135-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:iwl2000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:iwl2030-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:iwl3160-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:iwl3945-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:iwl4965-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:iwl5000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:iwl5150-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:iwl6000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:iwl6000g2a-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:iwl6000g2b-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:iwl6050-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:iwl7260-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:linux-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["iwl100-firmware-39.31.5.1-87.eulerosv2r8",
        "iwl1000-firmware-39.31.5.1-87.eulerosv2r8",
        "iwl105-firmware-18.168.6.1-87.eulerosv2r8",
        "iwl135-firmware-18.168.6.1-87.eulerosv2r8",
        "iwl2000-firmware-18.168.6.1-87.eulerosv2r8",
        "iwl2030-firmware-18.168.6.1-87.eulerosv2r8",
        "iwl3160-firmware-25.30.13.0-87.eulerosv2r8",
        "iwl3945-firmware-15.32.2.9-87.eulerosv2r8",
        "iwl4965-firmware-228.61.2.24-87.eulerosv2r8",
        "iwl5000-firmware-8.83.5.1_1-87.eulerosv2r8",
        "iwl5150-firmware-8.24.2.2-87.eulerosv2r8",
        "iwl6000-firmware-9.221.4.1-87.eulerosv2r8",
        "iwl6000g2a-firmware-18.168.6.1-87.eulerosv2r8",
        "iwl6000g2b-firmware-18.168.6.1-87.eulerosv2r8",
        "iwl6050-firmware-41.28.5.1-87.eulerosv2r8",
        "iwl7260-firmware-25.30.13.0-87.eulerosv2r8",
        "linux-firmware-20180913-87.git44d4fca9.eulerosv2r8"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-firmware");
}
