#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(141377);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-10713");
  script_xref(name:"CEA-ID", value:"CEA-2020-0061");

  script_name(english:"EulerOS Virtualization 3.0.2.2 : grub2 (EulerOS-SA-2020-2184)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the grub2 packages installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerability :

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

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2184
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb46ac7e");
  script_set_attribute(attribute:"solution", value:
"Update the affected grub2 package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10713");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-efi-x64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-pc-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-tools-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-tools-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.2.2") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.2");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["grub2-2.02-0.65.2.h15",
        "grub2-common-2.02-0.65.2.h15",
        "grub2-efi-x64-modules-2.02-0.65.2.h15",
        "grub2-pc-2.02-0.65.2.h15",
        "grub2-pc-modules-2.02-0.65.2.h15",
        "grub2-tools-2.02-0.65.2.h15",
        "grub2-tools-extra-2.02-0.65.2.h15",
        "grub2-tools-minimal-2.02-0.65.2.h15"];

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
