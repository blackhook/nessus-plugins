#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2021-1684.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151799);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/16");

  script_cve_id(
    "CVE-2020-14372",
    "CVE-2020-25632",
    "CVE-2020-25647",
    "CVE-2020-27749",
    "CVE-2020-27779",
    "CVE-2021-20225",
    "CVE-2021-20233"
  );
  script_xref(name:"IAVA", value:"2020-A-0349");
  script_xref(name:"ALAS", value:"2021-1684");

  script_name(english:"Amazon Linux 2 : grub2 (ALAS-2021-1684)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of grub2 installed on the remote host is prior to 2.06-2. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2021-1684 advisory.

  - A flaw was found in grub2 in versions prior to 2.06, where it incorrectly enables the usage of the ACPI
    command when Secure Boot is enabled. This flaw allows an attacker with privileged access to craft a
    Secondary System Description Table (SSDT) containing code to overwrite the Linux kernel lockdown variable
    content directly into memory. The table is further loaded and executed by the kernel, defeating its Secure
    Boot lockdown and allowing the attacker to load unsigned code. The highest threat from this vulnerability
    is to data confidentiality and integrity, as well as system availability. (CVE-2020-14372)

  - A flaw was found in grub2 in versions prior to 2.06. The rmmod implementation allows the unloading of a
    module used as a dependency without checking if any other dependent module is still loaded leading to a
    use-after-free scenario. This could allow arbitrary code to be executed or a bypass of Secure Boot
    protections. The highest threat from this vulnerability is to data confidentiality and integrity as well
    as system availability. (CVE-2020-25632)

  - A flaw was found in grub2 in versions prior to 2.06. During USB device initialization, descriptors are
    read with very little bounds checking and assumes the USB device is providing sane values. If properly
    exploited, an attacker could trigger memory corruption leading to arbitrary code execution allowing a
    bypass of the Secure Boot mechanism. The highest threat from this vulnerability is to data confidentiality
    and integrity as well as system availability. (CVE-2020-25647)

  - A flaw was found in grub2 in versions prior to 2.06. Variable names present are expanded in the supplied
    command line into their corresponding variable contents, using a 1kB stack buffer for temporary storage,
    without sufficient bounds checking. If the function is called with a command line that references a
    variable with a sufficiently large payload, it is possible to overflow the stack buffer, corrupt the stack
    frame and control execution which could also circumvent Secure Boot protections. The highest threat from
    this vulnerability is to data confidentiality and integrity as well as system availability.
    (CVE-2020-27749)

  - A flaw was found in grub2 in versions prior to 2.06. The cutmem command does not honor secure boot locking
    allowing an privileged attacker to remove address ranges from memory creating an opportunity to circumvent
    SecureBoot protections after proper triage about grub's memory layout. The highest threat from this
    vulnerability is to data confidentiality and integrity as well as system availability. (CVE-2020-27779)

  - A flaw was found in grub2 in versions prior to 2.06. The option parser allows an attacker to write past
    the end of a heap-allocated buffer by calling certain commands with a large number of specific short forms
    of options. The highest threat from this vulnerability is to data confidentiality and integrity as well as
    system availability. (CVE-2021-20225)

  - A flaw was found in grub2 in versions prior to 2.06. Setparam_prefix() in the menu rendering code performs
    a length calculation on the assumption that expressing a quoted single quote will require 3 characters,
    while it actually requires 4 characters which allows an attacker to corrupt memory by one byte for each
    quote in the input. The highest threat from this vulnerability is to data confidentiality and integrity as
    well as system availability. (CVE-2021-20233)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2021-1684.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14372");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25632");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25647");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-27749");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-27779");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-20225");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-20233");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update grub2' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20233");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-aa64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-aa64-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-aa64-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-aa64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-x64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-x64-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-x64-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-x64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-emu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-emu-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-pc-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-tools-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-tools-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-tools-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

pkgs = [
    {'reference':'grub2-2.06-2.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-2.06-2.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-common-2.06-2.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-debuginfo-2.06-2.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-debuginfo-2.06-2.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-aa64-2.06-2.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-aa64-cdboot-2.06-2.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-aa64-ec2-2.06-2.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-aa64-modules-2.06-2.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-x64-2.06-2.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-x64-cdboot-2.06-2.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-x64-ec2-2.06-2.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-x64-modules-2.06-2.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-emu-2.06-2.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-emu-2.06-2.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-emu-modules-2.06-2.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-emu-modules-2.06-2.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-pc-2.06-2.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-pc-modules-2.06-2.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-2.06-2.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-2.06-2.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-efi-2.06-2.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-extra-2.06-2.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-extra-2.06-2.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-minimal-2.06-2.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-minimal-2.06-2.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "grub2 / grub2-common / grub2-debuginfo / etc");
}