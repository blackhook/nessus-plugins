##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5443-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161809);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/23");

  script_cve_id("CVE-2022-29581", "CVE-2022-30594");
  script_xref(name:"USN", value:"5443-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS : Linux kernel vulnerabilities (USN-5443-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS host has a package installed that is affected by
multiple vulnerabilities as referenced in the USN-5443-1 advisory.

  - Improper Update of Reference Count vulnerability in net/sched of Linux Kernel allows local attacker to
    cause privilege escalation to root. This issue affects: Linux Kernel versions prior to 5.18; version 4.14
    and later versions. (CVE-2022-29581)

  - The Linux kernel before 5.17.2 mishandles seccomp permissions. The PTRACE_SEIZE code path allows attackers
    to bypass intended restrictions on setting the PT_SUSPEND_SECCOMP flag. (CVE-2022-30594)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5443-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29581");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-30594");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1095-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1111-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1116-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1124-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1129-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1130-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1130-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-180-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-180-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1024-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1025-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1027-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1028-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1028-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-44-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-44-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-44-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-44-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1004-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1005-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1006-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1007-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1008-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-33-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-33-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-33-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-33-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-33-lowlatency-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');
include('ksplice.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! preg(pattern:"^(16\.04|18\.04|20\.04|22\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var machine_kernel_release = get_kb_item_or_exit('Host/uname-r');
if (machine_kernel_release)
{
  var kernel_pattern;
  var kernel_mappings;
  var extra = '';
  if (preg(pattern:"^16.04$", string:os_release)) {
    kernel_pattern = "^4.15.0-\d+-(aws|aws-hwe|azure|gcp|generic|lowlatency|oracle)$";
    kernel_mappings = {
            "4.15.0-\d+(-aws|-aws-hwe)" : "4.15.0-1130",
            "4.15.0-\d+(-generic|-lowlatency)" : "4.15.0-180",
            "4.15.0-\d+-azure" : "4.15.0-1139",
            "4.15.0-\d+-gcp" : "4.15.0-1124",
            "4.15.0-\d+-oracle" : "4.15.0-1095"
    };
  };
  if (preg(pattern:"^18.04$", string:os_release)) {
    kernel_pattern = "^4.15.0-\d+-(aws|azure|gcp|generic|generic-lpae|kvm|lowlatency|oracle|raspi2|snapdragon)$";
    kernel_mappings = {
            "4.15.0-\d+(-generic|-generic-lpae|-lowlatency)" : "4.15.0-180",
            "4.15.0-\d+-aws" : "4.15.0-1130",
            "4.15.0-\d+-azure" : "4.15.0-1139",
            "4.15.0-\d+-gcp" : "4.15.0-1124",
            "4.15.0-\d+-kvm" : "4.15.0-1116",
            "4.15.0-\d+-oracle" : "4.15.0-1095",
            "4.15.0-\d+-raspi2" : "4.15.0-1111",
            "4.15.0-\d+-snapdragon" : "4.15.0-1129"
    };
  };
  if (preg(pattern:"^20.04$", string:os_release)) {
    kernel_pattern = "^5.13.0-\d+-(azure|generic|generic-64k|generic-lpae|lowlatency)$";
    kernel_mappings = {
            "5.13.0-\d+(-generic|-generic-64k|-generic-lpae|-lowlatency)" : "5.13.0-44",
            "5.13.0-\d+-azure" : "5.13.0-1025"
    };
  };
  if (preg(pattern:"^22.04$", string:os_release)) {
    kernel_pattern = "^5.15.0-\d+-(azure|gcp|generic|generic-64k|generic-lpae|ibm|lowlatency|lowlatency-64k|oracle|raspi|raspi-nolpae)$";
    kernel_mappings = {
            "5.15.0-\d+(-generic|-generic-64k|-generic-lpae|-lowlatency|-lowlatency-64k)" : "5.15.0-33",
            "5.15.0-\d+(-raspi|-raspi-nolpae)" : "5.15.0-1008",
            "5.15.0-\d+-azure" : "5.15.0-1007",
            "5.15.0-\d+-gcp" : "5.15.0-1005",
            "5.15.0-\d+-ibm" : "5.15.0-1004",
            "5.15.0-\d+-oracle" : "5.15.0-1006"
    };
  };
  if (! preg(pattern:kernel_pattern, string:machine_kernel_release)) audit(AUDIT_INST_VER_NOT_VULN, 'kernel ' + machine_kernel_release);

  var trimmed_kernel_release = ereg_replace(string:machine_kernel_release, pattern:"(-\D.*?)$", replace:'');
  foreach var kernel_regex (keys(kernel_mappings)) {
    if (preg(pattern:kernel_regex, string:machine_kernel_release)) {
      if (deb_ver_cmp(ver1:trimmed_kernel_release, ver2:kernel_mappings[kernel_regex]) < 0)
      {
        extra = extra + 'Running Kernel level of ' + trimmed_kernel_release + ' does not meet the minimum fixed level of ' + kernel_mappings[kernel_regex] + ' for this advisory.\n\n';
      }
      else
      {
        audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-5443-1');
      }
    }
  }
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-29581', 'CVE-2022-30594');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5443-1');
  }
  else
  {
    extra = extra + ksplice_reporting_text();
  }
}
if (extra) {
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : extra
  );
  exit(0);
}
