#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(140864);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/27");

  script_cve_id(
    "CVE-2014-3689",
    "CVE-2019-15890",
    "CVE-2019-20382",
    "CVE-2020-14364",
    "CVE-2020-15863"
  );
  script_bugtraq_id(70997);
  script_xref(name:"IAVB", value:"2020-B-0063-S");

  script_name(english:"EulerOS 2.0 SP3 : qemu-kvm (EulerOS-SA-2020-2097)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu-kvm packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - libslirp 4.0.0, as used in QEMU 4.1.0, has a
    use-after-free in ip_reass in
    ip_input.c.(CVE-2019-15890)

  - QEMU 4.1.0 has a memory leak in zrle_compress_data in
    ui/vnc-enc-zrle.c during a VNC disconnect operation
    because libz is misused, resulting in a situation where
    memory allocated in deflateInit2 is not freed in
    deflateEnd.(CVE-2019-20382)

  - An out-of-bounds read/write access flaw was found in
    the USB emulator of the QEMU in versions before 5.2.0.
    This issue occurs while processing USB packets from a
    guest when USBDevice 'setup_len' exceeds its
    'data_buf[4096]' in the do_token_in, do_token_out
    routines. This flaw allows a guest user to crash the
    QEMU process, resulting in a denial of service, or the
    potential execution of arbitrary code with the
    privileges of the QEMU process on the
    host.(CVE-2020-14364)

  - hw/net/xgmac.c in the XGMAC Ethernet controller in QEMU
    before 07-20-2020 has a buffer overflow. This occurs
    during packet transmission and affects the highbank and
    midway emulated machines. A guest user or process could
    use this flaw to crash the QEMU process on the host,
    resulting in a denial of service or potential
    privileged code execution. This was fixed in commit
    5519724a13664b43e225ca05351c60b4468e4555.(CVE-2020-1586
    3)

  - The vmware-vga driver (hw/display/vmware_vga.c) in QEMU
    allows local guest users to write to qemu memory
    locations and gain privileges via unspecified
    parameters related to rectangle
    handling.(CVE-2014-3689)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2097
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8fbd06c5");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu-kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15863");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["qemu-img-1.5.3-156.5.h16",
        "qemu-kvm-1.5.3-156.5.h16",
        "qemu-kvm-common-1.5.3-156.5.h16"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-kvm");
}
