#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0097. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154609);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/28");

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

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : grub2 Multiple Vulnerabilities (NS-SA-2021-0097)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has grub2 packages installed that are affected by
multiple vulnerabilities:

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
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0097");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-14372");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-25632");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-25647");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-27749");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-27779");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-20225");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-20233");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL grub2 packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20233");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-efi-ia32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-efi-ia32-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-efi-ia32-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-efi-x64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-efi-x64-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-efi-x64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-i386-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-pc-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-tools-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-tools-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-efi-ia32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-efi-ia32-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-efi-ia32-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-efi-x64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-efi-x64-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-efi-x64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-i386-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-pc-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-tools-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-tools-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'grub2-2.02-0.87.el7.centos.2.cgslv5.0.6.gc208268.lite',
    'grub2-common-2.02-0.87.el7.centos.2.cgslv5.0.6.gc208268.lite',
    'grub2-debuginfo-2.02-0.87.el7.centos.2.cgslv5.0.6.gc208268.lite',
    'grub2-efi-ia32-2.02-0.87.el7.centos.2.cgslv5.0.6.gc208268.lite',
    'grub2-efi-ia32-cdboot-2.02-0.87.el7.centos.2.cgslv5.0.6.gc208268.lite',
    'grub2-efi-ia32-modules-2.02-0.87.el7.centos.2.cgslv5.0.6.gc208268.lite',
    'grub2-efi-x64-2.02-0.87.el7.centos.2.cgslv5.0.6.gc208268.lite',
    'grub2-efi-x64-cdboot-2.02-0.87.el7.centos.2.cgslv5.0.6.gc208268.lite',
    'grub2-efi-x64-modules-2.02-0.87.el7.centos.2.cgslv5.0.6.gc208268.lite',
    'grub2-i386-modules-2.02-0.87.el7.centos.2.cgslv5.0.6.gc208268.lite',
    'grub2-lang-2.02-0.87.el7.centos.2.cgslv5.0.6.gc208268.lite',
    'grub2-pc-2.02-0.87.el7.centos.2.cgslv5.0.6.gc208268.lite',
    'grub2-pc-modules-2.02-0.87.el7.centos.2.cgslv5.0.6.gc208268.lite',
    'grub2-tools-2.02-0.87.el7.centos.2.cgslv5.0.6.gc208268.lite',
    'grub2-tools-extra-2.02-0.87.el7.centos.2.cgslv5.0.6.gc208268.lite',
    'grub2-tools-minimal-2.02-0.87.el7.centos.2.cgslv5.0.6.gc208268.lite'
  ],
  'CGSL MAIN 5.04': [
    'grub2-2.02-0.87.el7.centos.2.cgslv5.0.4.ga708edf',
    'grub2-common-2.02-0.87.el7.centos.2.cgslv5.0.4.ga708edf',
    'grub2-debuginfo-2.02-0.87.el7.centos.2.cgslv5.0.4.ga708edf',
    'grub2-efi-ia32-2.02-0.87.el7.centos.2.cgslv5.0.4.ga708edf',
    'grub2-efi-ia32-cdboot-2.02-0.87.el7.centos.2.cgslv5.0.4.ga708edf',
    'grub2-efi-ia32-modules-2.02-0.87.el7.centos.2.cgslv5.0.4.ga708edf',
    'grub2-efi-x64-2.02-0.87.el7.centos.2.cgslv5.0.4.ga708edf',
    'grub2-efi-x64-cdboot-2.02-0.87.el7.centos.2.cgslv5.0.4.ga708edf',
    'grub2-efi-x64-modules-2.02-0.87.el7.centos.2.cgslv5.0.4.ga708edf',
    'grub2-i386-modules-2.02-0.87.el7.centos.2.cgslv5.0.4.ga708edf',
    'grub2-pc-2.02-0.87.el7.centos.2.cgslv5.0.4.ga708edf',
    'grub2-pc-modules-2.02-0.87.el7.centos.2.cgslv5.0.4.ga708edf',
    'grub2-tools-2.02-0.87.el7.centos.2.cgslv5.0.4.ga708edf',
    'grub2-tools-extra-2.02-0.87.el7.centos.2.cgslv5.0.4.ga708edf',
    'grub2-tools-minimal-2.02-0.87.el7.centos.2.cgslv5.0.4.ga708edf'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'grub2');
}
