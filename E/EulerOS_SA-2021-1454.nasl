#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(147559);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-0305",
    "CVE-2020-12352",
    "CVE-2020-14331",
    "CVE-2020-14351",
    "CVE-2020-25643",
    "CVE-2020-25645",
    "CVE-2020-25705"
  );
  script_xref(name:"CEA-ID", value:"CEA-2020-0138");

  script_name(english:"EulerOS Virtualization 3.0.6.6 : kernel (EulerOS-SA-2021-1454)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - In cdev_get of char_dev.c, there is a possible
    use-after-free due to a race condition. This could lead
    to local escalation of privilege with System execution
    privileges needed. User interaction is not needed for
    exploitation.Product: AndroidVersions:
    Android-10Android ID: A-153467744(CVE-2020-0305)

  - A flaw was found in the Linux kernel's implementation
    of the invert video code on VGA consoles when a local
    attacker attempts to resize the console, calling an
    ioctl VT_RESIZE, which causes an out-of-bounds write to
    occur. This flaw allows a local user with access to the
    VGA console to crash the system, potentially escalating
    their privileges on the system. The highest threat from
    this vulnerability is to data confidentiality and
    integrity as well as system
    availability.(CVE-2020-14331)

  - To mitigate this issue, prevent the module nouveau from
    being loaded. Please see <a
    href='https://access.redhat.com/solutions/41278'>https:
    //access.redhat.com/solutions/41278</a> for information
    on how to blacklist a kernel module to prevent it from
    loading automatically.(CVE-2020-27820)

  - A flaw was found in the Linux kernel. A use-after-free
    memory flaw was found in the perf subsystem allowing a
    local attacker with permission to monitor perf events
    to corrupt memory and possibly escalate privileges. The
    highest threat from this vulnerability is to data
    confidentiality and integrity as well as system
    availability.(CVE-2020-14351)

  - A flaw was found in the HDLC_PPP module of the Linux
    kernel in versions before 5.9-rc7. Memory corruption
    and a read overflow is caused by improper input
    validation in the ppp_cp_parse_cr function which can
    cause the system to crash or cause a denial of service.
    The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system
    availability.(CVE-2020-25643)

  - A flaw was found in the Linux kernel in versions before
    5.9-rc7. Traffic between two Geneve endpoints may be
    unencrypted when IPsec is configured to encrypt traffic
    for the specific UDP port used by the GENEVE tunnel
    allowing anyone between the two endpoints to read the
    traffic unencrypted. The main threat from this
    vulnerability is to data
    confidentiality.(CVE-2020-25645)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1454
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f469041");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25643");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14351");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.6.6") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.6");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.6_122",
        "kernel-debuginfo-3.10.0-862.14.1.6_122",
        "kernel-debuginfo-common-x86_64-3.10.0-862.14.1.6_122",
        "kernel-devel-3.10.0-862.14.1.6_122",
        "kernel-headers-3.10.0-862.14.1.6_122",
        "kernel-source-3.10.0-862.14.1.6_122",
        "kernel-tools-3.10.0-862.14.1.6_122",
        "kernel-tools-debuginfo-3.10.0-862.14.1.6_122",
        "kernel-tools-libs-3.10.0-862.14.1.6_122",
        "kernel-tools-libs-devel-3.10.0-862.14.1.6_122",
        "perf-3.10.0-862.14.1.6_122",
        "perf-debuginfo-3.10.0-862.14.1.6_122",
        "python-perf-3.10.0-862.14.1.6_122",
        "python-perf-debuginfo-3.10.0-862.14.1.6_122"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
