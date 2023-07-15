##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161881);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2020-36516",
    "CVE-2022-1011",
    "CVE-2022-25258",
    "CVE-2022-25375",
    "CVE-2022-26490",
    "CVE-2022-26966",
    "CVE-2022-27666"
  );

  script_name(english:"EulerOS 2.0 SP10 : kernel (EulerOS-SA-2022-1791)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - An issue was discovered in the Linux kernel through 5.16.11. The mixed IPID assignment method with the
    hash-based IPID assignment policy allows an off-path attacker to inject data into a victim's TCP session
    or terminate that session. (CVE-2020-36516)

  - A use-after-free flaw was found in the Linux kernel's FUSE filesystem in the way a user triggers write().
    This flaw allows a local user to gain unauthorized access to data from the FUSE filesystem, resulting in
    privilege escalation. (CVE-2022-1011)

  - An issue was discovered in drivers/usb/gadget/composite.c in the Linux kernel before 5.16.10. The USB
    Gadget subsystem lacks certain validation of interface OS descriptor requests (ones with a large array
    index and ones associated with NULL function pointer retrieval). Memory corruption might occur.
    (CVE-2022-25258)

  - An issue was discovered in drivers/usb/gadget/function/rndis.c in the Linux kernel before 5.16.10. The
    RNDIS USB gadget lacks validation of the size of the RNDIS_MSG_SET command. Attackers can obtain sensitive
    information from kernel memory. (CVE-2022-25375)

  - st21nfca_connectivity_event_received in drivers/nfc/st21nfca/se.c in the Linux kernel through 5.16.12 has
    EVT_TRANSACTION buffer overflows because of untrusted length parameters. (CVE-2022-26490)

  - An issue was discovered in the Linux kernel before 5.16.12. drivers/net/usb/sr9700.c allows attackers to
    obtain sensitive information from heap memory via crafted frame lengths from a device. (CVE-2022-26966)

  - A heap buffer overflow flaw was found in IPsec ESP transformation code in net/ipv4/esp4.c and
    net/ipv6/esp6.c. This flaw allows a local attacker with a normal user privilege to overwrite kernel heap
    objects and may cause a local privilege escalation threat. (CVE-2022-27666)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1791
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba8ff9de");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36516");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-27666");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(10)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "kernel-4.19.90-vhulk2202.2.0.h1064.eulerosv2r10",
  "kernel-abi-stablelists-4.19.90-vhulk2202.2.0.h1064.eulerosv2r10",
  "kernel-tools-4.19.90-vhulk2202.2.0.h1064.eulerosv2r10",
  "kernel-tools-libs-4.19.90-vhulk2202.2.0.h1064.eulerosv2r10",
  "python3-perf-4.19.90-vhulk2202.2.0.h1064.eulerosv2r10"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"10", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
