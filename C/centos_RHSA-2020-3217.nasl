##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:3217 and
# CentOS Errata and Security Advisory 2020:3217 respectively.
##

include('compat.inc');

if (description)
{
  script_id(139236);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-10713",
    "CVE-2020-14308",
    "CVE-2020-14309",
    "CVE-2020-14310",
    "CVE-2020-14311",
    "CVE-2020-15705",
    "CVE-2020-15706",
    "CVE-2020-15707"
  );
  script_xref(name:"RHSA", value:"2020:3217");
  script_xref(name:"IAVA", value:"2020-A-0349");
  script_xref(name:"CEA-ID", value:"CEA-2020-0061");

  script_name(english:"CentOS 7 : grub2 (CESA-2020:3217)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2020:3217 advisory.

  - grub2: Crafted grub.cfg file can lead to arbitrary code execution during boot process (CVE-2020-10713)

  - grub2: grub_malloc does not validate allocation size allowing for arithmetic overflow and subsequent heap-
    based buffer overflow (CVE-2020-14308)

  - grub2: Integer overflow in grub_squash_read_symlink may lead to heap-based buffer overflow
    (CVE-2020-14309)

  - grub2: Integer overflow read_section_as_string may lead to heap-based buffer overflow (CVE-2020-14310)

  - grub2: Integer overflow in grub_ext2_read_link leads to heap-based buffer overflow (CVE-2020-14311)

  - grub2: Fail kernel validation without shim protocol (CVE-2020-15705)

  - grub2: Use-after-free redefining a function whilst the same function is already executing (CVE-2020-15706)

  - grub2: Integer overflow in initrd size handling (CVE-2020-15707)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.centos.org/pipermail/centos-announce/2020-July/035781.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c42bb45f");
  # https://lists.centos.org/pipermail/centos-announce/2020-July/035783.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c580a639");
  # https://lists.centos.org/pipermail/centos-announce/2020-July/035784.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7da4e0c5");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/78.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/122.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/190.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/416.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/440.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/787.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14309");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-10713");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(78, 122, 190, 416, 440, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:grub2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:grub2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:grub2-efi-ia32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:grub2-efi-ia32-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:grub2-efi-ia32-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:grub2-efi-x64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:grub2-efi-x64-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:grub2-efi-x64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:grub2-i386-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:grub2-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:grub2-pc-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:grub2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:grub2-tools-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:grub2-tools-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mokutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:shim-ia32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:shim-unsigned-ia32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:shim-unsigned-x64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:shim-x64");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'CentOS 7.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

pkgs = [
    {'reference':'grub2-2.02-0.86.el7.centos', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'grub2-common-2.02-0.86.el7.centos', 'release':'CentOS-7'},
    {'reference':'grub2-efi-ia32-2.02-0.86.el7.centos', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'grub2-efi-ia32-cdboot-2.02-0.86.el7.centos', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'grub2-efi-ia32-modules-2.02-0.86.el7.centos', 'release':'CentOS-7'},
    {'reference':'grub2-efi-x64-2.02-0.86.el7.centos', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'grub2-efi-x64-cdboot-2.02-0.86.el7.centos', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'grub2-efi-x64-modules-2.02-0.86.el7.centos', 'release':'CentOS-7'},
    {'reference':'grub2-i386-modules-2.02-0.86.el7.centos', 'release':'CentOS-7'},
    {'reference':'grub2-pc-2.02-0.86.el7.centos', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'grub2-pc-modules-2.02-0.86.el7.centos', 'release':'CentOS-7'},
    {'reference':'grub2-tools-2.02-0.86.el7.centos', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'grub2-tools-extra-2.02-0.86.el7.centos', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'grub2-tools-minimal-2.02-0.86.el7.centos', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'mokutil-15-7.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'shim-ia32-15-7.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'shim-unsigned-ia32-15-7.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'shim-unsigned-x64-15-7.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'shim-x64-15-7.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'grub2 / grub2-common / grub2-efi-ia32 / etc');
}
