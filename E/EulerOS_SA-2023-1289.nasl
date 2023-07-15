#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170819);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/30");

  script_cve_id("CVE-2021-3527", "CVE-2021-3682", "CVE-2021-20181");

  script_name(english:"EulerOS Virtualization 3.0.2.2 : qemu-kvm (EulerOS-SA-2023-1289)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu-kvm packages installed, the EulerOS Virtualization installation on the remote host
is affected by the following vulnerabilities :

  - A race condition flaw was found in the 9pfs server implementation of QEMU up to and including 5.2.0. This
    flaw allows a malicious 9p client to cause a use-after-free error, potentially escalating their privileges
    on the system. The highest threat from this vulnerability is to confidentiality, integrity as well as
    system availability. (CVE-2021-20181)

  - A flaw was found in the USB redirector device (usb-redir) of QEMU. Small USB packets are combined into a
    single, large transfer request, to reduce the overhead and improve performance. The combined size of the
    bulk transfer is used to dynamically allocate a variable length array (VLA) on the stack without proper
    validation. Since the total size is not bounded, a malicious guest could use this flaw to influence the
    array length and cause the QEMU process to perform an excessive allocation on the stack, resulting in a
    denial of service. (CVE-2021-3527)

  - A flaw was found in the USB redirector device emulation of QEMU in versions prior to 6.1.0-rc2. It occurs
    when dropping packets during a bulk transfer from a SPICE client due to the packet queue being full. A
    malicious SPICE client could use this flaw to make QEMU call free() with faked heap chunk metadata,
    resulting in a crash of QEMU or potential code execution with the privileges of the QEMU process on the
    host. (CVE-2021-3682)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1289
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7eca9d23");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu-kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20181");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3682");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.2");
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
if (uvp != "3.0.2.2") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.2");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "qemu-kvm-2.8.1-30.089",
  "qemu-kvm-common-2.8.1-30.089",
  "qemu-kvm-tools-2.8.1-30.089"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-kvm");
}
