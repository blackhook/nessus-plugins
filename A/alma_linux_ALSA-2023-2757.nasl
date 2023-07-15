#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2023:2757.
##

include('compat.inc');

if (description)
{
  script_id(176122);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/19");

  script_cve_id(
    "CVE-2021-46790",
    "CVE-2022-3165",
    "CVE-2022-30784",
    "CVE-2022-30786",
    "CVE-2022-30788",
    "CVE-2022-30789",
    "CVE-2023-1018"
  );
  script_xref(name:"ALSA", value:"2023:2757");

  script_name(english:"AlmaLinux 8 : virt:rhel and virt-devel:rhel (ALSA-2023:2757)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2023:2757 advisory.

  - ntfsck in NTFS-3G through 2021.8.22 has a heap-based buffer overflow involving buffer+512*3-2. NOTE: the
    upstream position is that ntfsck is deprecated; however, it is shipped by some Linux distributions.
    (CVE-2021-46790)

  - A crafted NTFS image can cause heap exhaustion in ntfs_get_attribute_value in NTFS-3G through 2021.8.22.
    (CVE-2022-30784)

  - A crafted NTFS image can cause a heap-based buffer overflow in ntfs_names_full_collate in NTFS-3G through
    2021.8.22. (CVE-2022-30786)

  - A crafted NTFS image can cause a heap-based buffer overflow in ntfs_mft_rec_alloc in NTFS-3G through
    2021.8.22. (CVE-2022-30788)

  - A crafted NTFS image can cause a heap-based buffer overflow in ntfs_check_log_client_array in NTFS-3G
    through 2021.8.22. (CVE-2022-30789)

  - An integer underflow issue was found in the QEMU VNC server while processing ClientCutText messages in the
    extended format. A malicious client could use this flaw to make QEMU unresponsive by sending a specially
    crafted payload message, resulting in a denial of service. (CVE-2022-3165)

  - An out-of-bounds read vulnerability exists in TPM2.0's Module Library allowing a 2-byte read past the end
    of a TPM2.0 command in the CryptParameterDecryption routine. An attacker who can successfully exploit this
    vulnerability can read or access sensitive data stored in the TPM. (CVE-2023-1018)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2023-2757.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30789");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(120, 122, 125, 191, 400, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:SLOF");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-appliance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-gfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-inspect-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-java-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-man-pages-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-man-pages-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-rescue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-rsync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-tools-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-xfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libiscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libiscsi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libiscsi-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libnbd-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libnbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:lua-guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdfuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:netcf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:netcf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:netcf-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:perl-Sys-Guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:perl-Sys-Virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:perl-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:seabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:seavgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:sgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:supermin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:supermin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:swtpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:swtpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:swtpm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:swtpm-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:swtpm-tools-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:virt-dib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::powertools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var appstreams = {
    'virt-devel:rhel': [
      {'reference':'hivex-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hivex-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hivex-devel-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hivex-devel-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-appliance-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-appliance-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-devel-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-devel-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gfs2-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gfs2-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-devel-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-devel-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-devel-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-devel-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rescue-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rescue-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rsync-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rsync-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-tools-c-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-tools-c-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-xfs-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-xfs-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libiscsi-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-devel-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-devel-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-utils-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-utils-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-1.6.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-1.6.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-devel-1.6.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-devel-1.6.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-dbus-1.3.0-2.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-dbus-1.3.0-2.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'lua-guestfs-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'lua-guestfs-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nbdfuse-1.6.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdfuse-1.6.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-devel-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-devel-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-libs-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-libs-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-hivex-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-hivex-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sys-Guestfs-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Sys-Guestfs-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Sys-Virt-8.0.0-1.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sys-Virt-8.0.0-1.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-hivex-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-hivex-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libguestfs-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python3-libguestfs-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python3-libnbd-1.6.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libnbd-1.6.0-5.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libvirt-8.0.0-2.module_el8.7.0+3346+68867adb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libvirt-8.0.0-2.module_el8.7.0+3346+68867adb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-hivex-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-hivex-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libguestfs-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ruby-libguestfs-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'seabios-1.16.0-3.module_el8.7.0+3346+68867adb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seabios-1.16.0-3.module_el8.7.0+3346+68867adb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sgabios-0.20170427git-3.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'sgabios-0.20170427git-3.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'supermin-5.2.1-2.module_el8.7.0+3346+68867adb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'supermin-5.2.1-2.module_el8.7.0+3346+68867adb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'supermin-devel-5.2.1-2.module_el8.7.0+3346+68867adb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'supermin-devel-5.2.1-2.module_el8.7.0+3346+68867adb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-devel-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-devel-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-libs-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-libs-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-tools-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-tools-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-tools-pkcs11-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-tools-pkcs11-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'virt-dib-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-dib-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ],
    'virt:rhel': [
      {'reference':'libguestfs-bash-completion-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-inspect-icons-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-javadoc-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-man-pages-ja-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-man-pages-uk-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-tools-1.44.0-9.module_el8.7.0+3402+b6326d23.alma', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libnbd-bash-completion-1.6.0-5.module_el8.6.0+2880+7d9e3703', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seabios-bin-1.16.0-3.module_el8.7.0+3346+68867adb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seavgabios-bin-1.16.0-3.module_el8.7.0+3346+68867adb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sgabios-bin-0.20170427git-3.module_el8.6.0+2880+7d9e3703', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'SLOF-20210217-1.module_el8.6.0+2880+7d9e3703', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/AlmaLinux/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      var exists_check = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
      if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module virt-devel:rhel / virt:rhel');

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'SLOF / hivex / hivex-devel / libguestfs / libguestfs-appliance / etc');
}
