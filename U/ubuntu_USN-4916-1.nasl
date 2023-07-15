##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4916-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148691);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/18");

  script_cve_id("CVE-2021-3493", "CVE-2021-29154");
  script_xref(name:"USN", value:"4916-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/11/10");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : Linux kernel vulnerabilities (USN-4916-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4916-1 advisory.

  - BPF JIT compilers in the Linux kernel through 5.11.12 have incorrect computation of branch displacements,
    allowing them to execute arbitrary code within the kernel context. This affects
    arch/x86/net/bpf_jit_comp.c and arch/x86/net/bpf_jit_comp32.c. (CVE-2021-29154)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4916-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3493");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'2021 Ubuntu Overlayfs LPE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1017-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1070-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1084-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1090-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1098-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1099-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1101-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1113-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-142-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-142-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-142-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1091-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1092-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1127-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1151-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1155-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-209-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-209-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-209-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-xenial");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('ksplice.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(16\.04|18\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  cve_list = make_list('CVE-2021-3493', 'CVE-2021-29154');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4916-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

pkgs = [
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1070-oracle', 'pkgver': '4.15.0-1070.78~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1098-gcp', 'pkgver': '4.15.0-1098.111~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1099-aws', 'pkgver': '4.15.0-1099.106~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1113-azure', 'pkgver': '4.15.0-1113.126~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-142-generic', 'pkgver': '4.15.0-142.146~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-142-generic-lpae', 'pkgver': '4.15.0-142.146~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-142-lowlatency', 'pkgver': '4.15.0-142.146~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-1092-kvm', 'pkgver': '4.4.0-1092.101'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-1127-aws', 'pkgver': '4.4.0-1127.141'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-1151-raspi2', 'pkgver': '4.4.0-1151.162'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-1155-snapdragon', 'pkgver': '4.4.0-1155.165'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-209-generic', 'pkgver': '4.4.0-209.241'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-209-generic-lpae', 'pkgver': '4.4.0-209.241'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-209-lowlatency', 'pkgver': '4.4.0-209.241'},
    {'osver': '16.04', 'pkgname': 'linux-image-aws', 'pkgver': '4.4.0.1127.132'},
    {'osver': '16.04', 'pkgname': 'linux-image-aws-hwe', 'pkgver': '4.15.0.1099.92'},
    {'osver': '16.04', 'pkgname': 'linux-image-azure', 'pkgver': '4.15.0.1113.104'},
    {'osver': '16.04', 'pkgname': 'linux-image-azure-edge', 'pkgver': '4.15.0.1113.104'},
    {'osver': '16.04', 'pkgname': 'linux-image-gcp', 'pkgver': '4.15.0.1098.99'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic', 'pkgver': '4.4.0.209.215'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-hwe-16.04', 'pkgver': '4.15.0.142.137'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.142.137'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '4.4.0.209.215'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.142.137'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.142.137'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lpae-lts-utopic', 'pkgver': '4.4.0.209.215'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lpae-lts-vivid', 'pkgver': '4.4.0.209.215'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lpae-lts-wily', 'pkgver': '4.4.0.209.215'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lpae-lts-xenial', 'pkgver': '4.4.0.209.215'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-utopic', 'pkgver': '4.4.0.209.215'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-vivid', 'pkgver': '4.4.0.209.215'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-wily', 'pkgver': '4.4.0.209.215'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-xenial', 'pkgver': '4.4.0.209.215'},
    {'osver': '16.04', 'pkgname': 'linux-image-gke', 'pkgver': '4.15.0.1098.99'},
    {'osver': '16.04', 'pkgname': 'linux-image-kvm', 'pkgver': '4.4.0.1092.90'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '4.4.0.209.215'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.142.137'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.142.137'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-utopic', 'pkgver': '4.4.0.209.215'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-vivid', 'pkgver': '4.4.0.209.215'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-wily', 'pkgver': '4.4.0.209.215'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-xenial', 'pkgver': '4.4.0.209.215'},
    {'osver': '16.04', 'pkgname': 'linux-image-oem', 'pkgver': '4.15.0.142.137'},
    {'osver': '16.04', 'pkgname': 'linux-image-oracle', 'pkgver': '4.15.0.1070.58'},
    {'osver': '16.04', 'pkgname': 'linux-image-raspi2', 'pkgver': '4.4.0.1151.151'},
    {'osver': '16.04', 'pkgname': 'linux-image-snapdragon', 'pkgver': '4.4.0.1155.147'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual', 'pkgver': '4.4.0.209.215'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-hwe-16.04', 'pkgver': '4.15.0.142.137'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.142.137'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-utopic', 'pkgver': '4.4.0.209.215'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-vivid', 'pkgver': '4.4.0.209.215'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-wily', 'pkgver': '4.4.0.209.215'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-xenial', 'pkgver': '4.4.0.209.215'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1017-dell300x', 'pkgver': '4.15.0-1017.21'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1070-oracle', 'pkgver': '4.15.0-1070.78'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1084-raspi2', 'pkgver': '4.15.0-1084.89'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1090-kvm', 'pkgver': '4.15.0-1090.92'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1098-gcp', 'pkgver': '4.15.0-1098.111'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1099-aws', 'pkgver': '4.15.0-1099.106'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1101-snapdragon', 'pkgver': '4.15.0-1101.110'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1113-azure', 'pkgver': '4.15.0-1113.126'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-142-generic', 'pkgver': '4.15.0-142.146'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-142-generic-lpae', 'pkgver': '4.15.0-142.146'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-142-lowlatency', 'pkgver': '4.15.0-142.146'},
    {'osver': '18.04', 'pkgname': 'linux-image-aws-lts-18.04', 'pkgver': '4.15.0.1099.102'},
    {'osver': '18.04', 'pkgname': 'linux-image-azure-lts-18.04', 'pkgver': '4.15.0.1113.86'},
    {'osver': '18.04', 'pkgname': 'linux-image-dell300x', 'pkgver': '4.15.0.1017.19'},
    {'osver': '18.04', 'pkgname': 'linux-image-gcp-lts-18.04', 'pkgver': '4.15.0.1098.116'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic', 'pkgver': '4.15.0.142.129'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-16.04', 'pkgver': '4.15.0.142.129'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.142.129'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '4.15.0.142.129'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.142.129'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.142.129'},
    {'osver': '18.04', 'pkgname': 'linux-image-kvm', 'pkgver': '4.15.0.1090.86'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '4.15.0.142.129'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.142.129'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.142.129'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle-lts-18.04', 'pkgver': '4.15.0.1070.80'},
    {'osver': '18.04', 'pkgname': 'linux-image-raspi2', 'pkgver': '4.15.0.1084.81'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon', 'pkgver': '4.15.0.1101.104'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual', 'pkgver': '4.15.0.142.129'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-16.04', 'pkgver': '4.15.0.142.129'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.142.129'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-image-4.15.0-1017-dell300x / linux-image-4.15.0-1070-oracle / etc');
}