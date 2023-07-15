#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151256);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/06");

  script_cve_id(
    "CVE-2020-14372",
    "CVE-2020-25632",
    "CVE-2020-25647",
    "CVE-2021-20225",
    "CVE-2021-20233"
  );

  script_name(english:"EulerOS Virtualization 3.0.6.6 : grub2 (EulerOS-SA-2021-2027)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the grub2 packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A flaw was found in grub2 in versions prior to 2.06.
    Setparam_prefix() in the menu rendering code performs a
    length calculation on the assumption that expressing a
    quoted single quote will require 3 characters, while it
    actually requires 4 characters which allows an attacker
    to corrupt memory by one byte for each quote in the
    input. The highest threat from this vulnerability is to
    data confidentiality and integrity as well as system
    availability.(CVE-2021-20233)

  - A flaw was found in grub2 in versions prior to 2.06.
    The option parser allows an attacker to write past the
    end of a heap-allocated buffer by calling certain
    commands with a large number of specific short forms of
    options. The highest threat from this vulnerability is
    to data confidentiality and integrity as well as system
    availability.(CVE-2021-20225)

  - A flaw was found in grub2. During USB device
    initialization, descriptors are read with very little
    bounds checking and assumes the USB device is providing
    sane values. If properly exploited, an attacker could
    trigger memory corruption leading to arbitrary code
    execution allowing a bypass of the Secure Boot
    mechanism. The highest threat from this vulnerability
    is to data confidentiality and integrity as well as
    system availability.(CVE-2020-25647)

  - A flaw was found in grub2 in versions prior to 2.06.
    The rmmod implementation allows the unloading of a
    module used as a dependency without checking if any
    other dependent module is still loaded leading to a
    use-after-free scenario. This could allow arbitrary
    code to be executed or a bypass of Secure Boot
    protections. The highest threat from this vulnerability
    is to data confidentiality and integrity as well as
    system availability.(CVE-2020-25632)

  - A flaw was found in grub2 in versions prior to 2.06,
    where it incorrectly enables the usage of the ACPI
    command when Secure Boot is enabled. This flaw allows
    an attacker with privileged access to craft a Secondary
    System Description Table (SSDT) containing code to
    overwrite the Linux kernel lockdown variable content
    directly into memory. The table is further loaded and
    executed by the kernel, defeating its Secure Boot
    lockdown and allowing the attacker to load unsigned
    code. The highest threat from this vulnerability is to
    data confidentiality and integrity, as well as system
    availability.(CVE-2020-14372)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2027
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80300891");
  script_set_attribute(attribute:"solution", value:
"Update the affected grub2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-efi-ia32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-efi-ia32-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-efi-x64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-efi-x64-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-efi-x64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-pc-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-tools-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-tools-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["grub2-2.02-0.65.2.h22.eulerosv2r7",
        "grub2-common-2.02-0.65.2.h22.eulerosv2r7",
        "grub2-efi-ia32-2.02-0.65.2.h22.eulerosv2r7",
        "grub2-efi-ia32-cdboot-2.02-0.65.2.h22.eulerosv2r7",
        "grub2-efi-x64-2.02-0.65.2.h22.eulerosv2r7",
        "grub2-efi-x64-cdboot-2.02-0.65.2.h22.eulerosv2r7",
        "grub2-efi-x64-modules-2.02-0.65.2.h22.eulerosv2r7",
        "grub2-pc-2.02-0.65.2.h22.eulerosv2r7",
        "grub2-pc-modules-2.02-0.65.2.h22.eulerosv2r7",
        "grub2-tools-2.02-0.65.2.h22.eulerosv2r7",
        "grub2-tools-extra-2.02-0.65.2.h22.eulerosv2r7",
        "grub2-tools-minimal-2.02-0.65.2.h22.eulerosv2r7"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "grub2");
}
