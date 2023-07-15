#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6024-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174449);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/19");

  script_cve_id(
    "CVE-2022-3424",
    "CVE-2022-41218",
    "CVE-2022-47929",
    "CVE-2023-0468",
    "CVE-2023-1032",
    "CVE-2023-1281",
    "CVE-2023-22997",
    "CVE-2023-26545",
    "CVE-2023-26606",
    "CVE-2023-28328"
  );
  script_xref(name:"USN", value:"6024-1");

  script_name(english:"Ubuntu 22.04 LTS / 22.10 : Linux kernel vulnerabilities (USN-6024-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS / 22.10 host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-6024-1 advisory.

  - A use-after-free flaw was found in the Linux kernel's SGI GRU driver in the way the first
    gru_file_unlocked_ioctl function is called by the user, where a fail pass occurs in the
    gru_check_chiplet_assignment function. This flaw allows a local user to crash or potentially escalate
    their privileges on the system. (CVE-2022-3424)

  - In drivers/media/dvb-core/dmxdev.c in the Linux kernel through 5.19.10, there is a use-after-free caused
    by refcount races, affecting dvb_demux_open and dvb_dmxdev_release. (CVE-2022-41218)

  - In the Linux kernel before 6.1.6, a NULL pointer dereference bug in the traffic control subsystem allows
    an unprivileged user to trigger a denial of service (system crash) via a crafted traffic control
    configuration that is set up with tc qdisc and tc class commands. This affects qdisc_graft in
    net/sched/sch_api.c. (CVE-2022-47929)

  - A use-after-free flaw was found in io_uring/poll.c in io_poll_check_events in the io_uring subcomponent in
    the Linux Kernel due to a race condition of poll_refs. This flaw may cause a NULL pointer dereference.
    (CVE-2023-0468)

  - Use After Free vulnerability in Linux kernel traffic control index filter (tcindex) allows Privilege
    Escalation. The imperfect hash area can be updated while packets are traversing, which will cause a use-
    after-free when 'tcf_exts_exec()' is called with the destroyed tcf_ext. A local attacker user can use this
    vulnerability to elevate its privileges to root. This issue affects Linux Kernel: from 4.14 before git
    commit ee059170b1f7e94e55fa6cadee544e176a6e59c2. (CVE-2023-1281)

  - In the Linux kernel before 6.1.2, kernel/module/decompress.c misinterprets the module_get_next_page return
    value (expects it to be NULL in the error case, whereas it is actually an error pointer). (CVE-2023-22997)

  - In the Linux kernel before 6.1.13, there is a double free in net/mpls/af_mpls.c upon an allocation failure
    (for registering the sysctl table under a new location) during the renaming of a device. (CVE-2023-26545)

  - In the Linux kernel 6.0.8, there is a use-after-free in ntfs_trim_fs in fs/ntfs3/bitmap.c.
    (CVE-2023-26606)

  - kernel: Type confusion in pick_next_rt_entity(), which can result in memory corruption. (CVE-2023-1077)
    (CVE-2023-1032)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6024-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-26606");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image--aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image--azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image--generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image--generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image--generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image--lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image--lowlatency-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image--raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image--raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.19.0-1016--raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.19.0-1016--raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.19.0-1020-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.19.0-1021-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.19.0-1022--lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.19.0-1022--lowlatency-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.19.0-1023--aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.19.0-1023--azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.19.0-40--generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.19.0-40--generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.19.0-40--generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023 Canonical, Inc. / NASL script (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(22\.04|22\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04 / 22.10', 'Ubuntu ' + os_release);
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
  if (preg(pattern:"^22.04$", string:os_release)) {
    kernel_pattern = "^5.19.0-\d+-(generic|generic-64k|generic-lpae)$";
    kernel_mappings = {
            "5.19.0-\d+(-generic|-generic-64k|-generic-lpae)" : "5.19.0-40"
    };
  };
  if (preg(pattern:"^22.10$", string:os_release)) {
    kernel_pattern = "^5.19.0-\d+-(aws|azure|generic|generic-64k|generic-lpae|kvm|lowlatency|lowlatency-64k|oracle|raspi|raspi-nolpae)$";
    kernel_mappings = {
            "5.19.0-\d+(-aws|-azure)" : "5.19.0-1023",
            "5.19.0-\d+(-generic|-generic-64k|-generic-lpae)" : "5.19.0-40",
            "5.19.0-\d+(-lowlatency|-lowlatency-64k)" : "5.19.0-1022",
            "5.19.0-\d+(-raspi|-raspi-nolpae)" : "5.19.0-1016",
            "5.19.0-\d+-kvm" : "5.19.0-1021",
            "5.19.0-\d+-oracle" : "5.19.0-1020"
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
        audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6024-1');
      }
    }
  }
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-3424', 'CVE-2022-41218', 'CVE-2022-47929', 'CVE-2023-0468', 'CVE-2023-1032', 'CVE-2023-1281', 'CVE-2023-22997', 'CVE-2023-26545', 'CVE-2023-26606', 'CVE-2023-28328');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6024-1');
  }
  else
  {
    extra = extra + ksplice_reporting_text();
  }
}
if (extra) {
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : extra
  );
  exit(0);
}
