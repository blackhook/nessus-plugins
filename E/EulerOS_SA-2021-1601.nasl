#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(147445);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-10713",
    "CVE-2020-14308",
    "CVE-2020-14309",
    "CVE-2020-14310",
    "CVE-2020-14311",
    "CVE-2020-15706",
    "CVE-2020-15707"
  );
  script_xref(name:"CEA-ID", value:"CEA-2020-0061");

  script_name(english:"EulerOS Virtualization 2.9.1 : grub2 (EulerOS-SA-2021-1601)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the grub2 packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A flaw was found in grub2, prior to version 2.06. An
    attacker may use the GRUB 2 flaw to hijack and tamper
    the GRUB verification process. This flaw also allows
    the bypass of Secure Boot protections. In order to load
    an untrusted or modified kernel, an attacker would
    first need to establish access to the system such as
    gaining physical access, obtain the ability to alter a
    pxe-boot network, or have remote access to a networked
    system with root access. With this access, an attacker
    could then craft a string to cause a buffer overflow by
    injecting a malicious payload that leads to arbitrary
    code execution within GRUB. The highest threat from
    this vulnerability is to data confidentiality and
    integrity as well as system
    availability.(CVE-2020-10713)

  - Integer overflows were discovered in the functions
    grub_cmd_initrd and grub_initrd_init in the efilinux
    component of GRUB2, as shipped in Debian, Red Hat, and
    Ubuntu (the functionality is not included in GRUB2
    upstream), leading to a heap-based buffer overflow.
    These could be triggered by an extremely large number
    of arguments to the initrd command on 32-bit
    architectures, or a crafted filesystem with very large
    files on any architecture. An attacker could use this
    to execute arbitrary code and bypass UEFI Secure Boot
    restrictions. This issue affects GRUB2 version 2.04 and
    prior versions.(CVE-2020-15707)

  - GRUB2 contains a race condition in
    grub_script_function_create() leading to a
    use-after-free vulnerability which can be triggered by
    redefining a function whilst the same function is
    already executing, leading to arbitrary code execution
    and secure boot restriction bypass. This issue affects
    GRUB2 version 2.04 and prior versions.(CVE-2020-15706)

  - There is an issue with grub2 before version 2.06 while
    handling symlink on ext filesystems. A filesystem
    containing a symbolic link with an inode size of
    UINT32_MAX causes an arithmetic overflow leading to a
    zero-sized memory allocation with subsequent heap-based
    buffer overflow.(CVE-2020-14311)

  - There is an issue on grub2 before version 2.06 at
    function read_section_as_string(). It expects a font
    name to be at max UINT32_MAX - 1 length in bytes but it
    doesn't verify it before proceed with buffer allocation
    to read the value from the font value. An attacker may
    leverage that by crafting a malicious font file which
    has a name with UINT32_MAX, leading to
    read_section_as_string() to an arithmetic overflow,
    zero-sized allocation and further heap-based buffer
    overflow.(CVE-2020-14310)

  - There's an issue with grub2 in all versions before 2.06
    when handling squashfs filesystems containing a
    symbolic link with name length of UINT32 bytes in size.
    The name size leads to an arithmetic overflow leading
    to a zero-size allocation further causing a heap-based
    buffer overflow with attacker controlled
    data.(CVE-2020-14309)

  - In grub2 versions before 2.06 the grub memory allocator
    doesn't check for possible arithmetic overflows on the
    requested allocation size. This leads the function to
    return invalid memory allocations which can be further
    used to cause possible integrity, confidentiality and
    availability impacts during the boot
    process.(CVE-2020-14308)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1601
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e554f72");
  script_set_attribute(attribute:"solution", value:
"Update the affected grub2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14309");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-10713");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-efi-aa64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-efi-aa64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.9.1");
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
if (uvp != "2.9.1") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.9.1");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["grub2-common-2.02-73.h20.eulerosv2r9",
        "grub2-efi-aa64-2.02-73.h20.eulerosv2r9",
        "grub2-efi-aa64-modules-2.02-73.h20.eulerosv2r9",
        "grub2-tools-2.02-73.h20.eulerosv2r9"];

foreach (pkg in pkgs)
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "grub2");
}
