##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:1016. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(135080);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id(
    "CVE-2015-9289",
    "CVE-2017-17807",
    "CVE-2018-7191",
    "CVE-2018-19985",
    "CVE-2018-20169",
    "CVE-2019-3901",
    "CVE-2019-9503",
    "CVE-2019-10207",
    "CVE-2019-10638",
    "CVE-2019-10639",
    "CVE-2019-11190",
    "CVE-2019-11884",
    "CVE-2019-12382",
    "CVE-2019-13233",
    "CVE-2019-13648",
    "CVE-2019-14283",
    "CVE-2019-15916",
    "CVE-2019-16746",
    "CVE-2019-18660"
  );
  script_bugtraq_id(
    89937,
    102301,
    107528,
    107890,
    108011,
    108299,
    108380,
    108474,
    109055,
    109092
  );
  script_xref(name:"RHSA", value:"2020:1016");

  script_name(english:"RHEL 7 : kernel (RHSA-2020:1016)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:1016 advisory.

  - kernel: out of bound read in DVB connexant driver. (CVE-2015-9289)

  - kernel: Missing permissions check for request_key() destination allows local attackers to add keys to
    keyring without Write permission (CVE-2017-17807)

  - kernel: oob memory read in hso_probe in drivers/net/usb/hso.c (CVE-2018-19985)

  - kernel: usb: missing size check in the __usb_get_extra_descriptor() leading to DoS (CVE-2018-20169)

  - kernel: denial of service via ioctl call in network tun handling (CVE-2018-7191)

  - kernel: null-pointer dereference in hci_uart_set_flow_control (CVE-2019-10207)

  - Kernel: net: weak IP ID generation leads to remote device tracking (CVE-2019-10638)

  - Kernel: net: using kernel space address bits to derive IP ID may potentially break KASLR (CVE-2019-10639)

  - kernel: ASLR bypass for setuid binaries due to late install_exec_creds() (CVE-2019-11190)

  - kernel: sensitive information disclosure from kernel stack memory via HIDPCONNADD command (CVE-2019-11884)

  - kernel: unchecked kstrdup of fwstr in drm_load_edid_firmware leads to denial of service (CVE-2019-12382)

  - kernel: use-after-free in arch/x86/lib/insn-eval.c (CVE-2019-13233)

  - kernel: denial of service in arch/powerpc/kernel/signal_32.c and arch/powerpc/kernel/signal_64.c via
    sigreturn() system call (CVE-2019-13648)

  - kernel: integer overflow and OOB read in drivers/block/floppy.c (CVE-2019-14283)

  - kernel: heap overflow in mwifiex_set_uap_rates() function of Marvell Wifi Driver leading to DoS
    (CVE-2019-14814)

  - kernel: heap-overflow in mwifiex_set_wmm_params() function of Marvell WiFi driver leading to DoS
    (CVE-2019-14815)

  - kernel: An out-of-bounds read in drivers/scsi/qedi/qedi_dbg.c leading to crash or information disclosure
    (CVE-2019-15090)

  - kernel: use-after-free in sound/core/init.c and sound/core/info.c (CVE-2019-15214)

  - kernel: Null pointer dereference in the sound/usb/line6/pcm.c (CVE-2019-15221)

  - kernel: memory leak in register_queue_kobjects() in net/core/net-sysfs.c leads to denial of service
    (CVE-2019-15916)

  - kernel: buffer-overflow hardening in WiFi beacon validation code. (CVE-2019-16746)

  - kernel: powerpc: incomplete Spectre-RSB mitigation leads to information exposure (CVE-2019-18660)

  - kernel: perf_event_open() and execve() race in setuid programs allows a data leak (CVE-2019-3901)

  - kernel: triggering AP to send IAPP location updates for stations before the required authentication
    process has completed can lead to DoS (CVE-2019-5108)

  - kernel: brcmfmac frame validation bypass (CVE-2019-9503)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2015-9289");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2017-17807");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-7191");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-19985");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-20169");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-3901");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-5108");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-9503");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10207");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10638");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10639");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11190");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11884");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-12382");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-13233");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-13648");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14283");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14814");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14815");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15090");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15214");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15221");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15916");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-16746");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-18660");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:1016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1528335");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1660385");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1666106");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1699856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1701245");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1701842");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1709837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1715554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1716328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1727756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1729931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1729933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1733874");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1734243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1735630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1735655");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1743526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1743591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1744130");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1744137");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1749974");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1750813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1760306");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1777825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1789927");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9503");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-16746");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 120, 122, 125, 190, 200, 250, 253, 331, 362, 400, 416, 440, 476, 667, 787, 862);

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-bootwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2015-9289', 'CVE-2017-17807', 'CVE-2018-7191', 'CVE-2018-19985', 'CVE-2018-20169', 'CVE-2019-3901', 'CVE-2019-5108', 'CVE-2019-9503', 'CVE-2019-10207', 'CVE-2019-10638', 'CVE-2019-10639', 'CVE-2019-11190', 'CVE-2019-11884', 'CVE-2019-12382', 'CVE-2019-13233', 'CVE-2019-13648', 'CVE-2019-14283', 'CVE-2019-14814', 'CVE-2019-14815', 'CVE-2019-15090', 'CVE-2019-15214', 'CVE-2019-15221', 'CVE-2019-15916', 'CVE-2019-16746', 'CVE-2019-18660');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2020:1016');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/supplementary/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/debug',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/debug',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/os',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/os',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/debug',
      'content/dist/rhel/client/7/7Client/x86_64/optional/debug',
      'content/dist/rhel/client/7/7Client/x86_64/optional/os',
      'content/dist/rhel/client/7/7Client/x86_64/optional/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/oracle-java-rm/os',
      'content/dist/rhel/client/7/7Client/x86_64/os',
      'content/dist/rhel/client/7/7Client/x86_64/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/supplementary/debug',
      'content/dist/rhel/client/7/7Client/x86_64/supplementary/os',
      'content/dist/rhel/client/7/7Client/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/oracle-java-rm/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/supplementary/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/supplementary/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap-hana/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap-hana/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap-hana/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/supplementary/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/supplementary/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/debug',
      'content/dist/rhel/power/7/7Server/ppc64/optional/debug',
      'content/dist/rhel/power/7/7Server/ppc64/optional/os',
      'content/dist/rhel/power/7/7Server/ppc64/optional/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/os',
      'content/dist/rhel/power/7/7Server/ppc64/sap/debug',
      'content/dist/rhel/power/7/7Server/ppc64/sap/os',
      'content/dist/rhel/power/7/7Server/ppc64/sap/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/supplementary/debug',
      'content/dist/rhel/power/7/7Server/ppc64/supplementary/os',
      'content/dist/rhel/power/7/7Server/ppc64/supplementary/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/debug',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/debug',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/os',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/debug',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/os',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/optional/debug',
      'content/dist/rhel/server/7/7Server/x86_64/optional/os',
      'content/dist/rhel/server/7/7Server/x86_64/optional/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/oracle-java-rm/os',
      'content/dist/rhel/server/7/7Server/x86_64/os',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/debug',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/os',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rt/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rt/os',
      'content/dist/rhel/server/7/7Server/x86_64/rt/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/sap-hana/debug',
      'content/dist/rhel/server/7/7Server/x86_64/sap-hana/os',
      'content/dist/rhel/server/7/7Server/x86_64/sap-hana/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/sap/debug',
      'content/dist/rhel/server/7/7Server/x86_64/sap/os',
      'content/dist/rhel/server/7/7Server/x86_64/sap/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/supplementary/debug',
      'content/dist/rhel/server/7/7Server/x86_64/supplementary/os',
      'content/dist/rhel/server/7/7Server/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/os',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/os',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/os',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/os',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/sap/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/sap/os',
      'content/dist/rhel/system-z/7/7Server/s390x/sap/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/supplementary/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/supplementary/os',
      'content/dist/rhel/system-z/7/7Server/s390x/supplementary/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/oracle-java-rm/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/supplementary/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/supplementary/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/supplementary/source/SRPMS',
      'content/fastrack/rhel/client/7/x86_64/debug',
      'content/fastrack/rhel/client/7/x86_64/optional/debug',
      'content/fastrack/rhel/client/7/x86_64/optional/os',
      'content/fastrack/rhel/client/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/client/7/x86_64/os',
      'content/fastrack/rhel/client/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/computenode/7/x86_64/debug',
      'content/fastrack/rhel/computenode/7/x86_64/optional/debug',
      'content/fastrack/rhel/computenode/7/x86_64/optional/os',
      'content/fastrack/rhel/computenode/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/computenode/7/x86_64/os',
      'content/fastrack/rhel/computenode/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/power/7/ppc64/debug',
      'content/fastrack/rhel/power/7/ppc64/optional/debug',
      'content/fastrack/rhel/power/7/ppc64/optional/os',
      'content/fastrack/rhel/power/7/ppc64/optional/source/SRPMS',
      'content/fastrack/rhel/power/7/ppc64/os',
      'content/fastrack/rhel/power/7/ppc64/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/debug',
      'content/fastrack/rhel/server/7/x86_64/highavailability/debug',
      'content/fastrack/rhel/server/7/x86_64/highavailability/os',
      'content/fastrack/rhel/server/7/x86_64/highavailability/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/optional/debug',
      'content/fastrack/rhel/server/7/x86_64/optional/os',
      'content/fastrack/rhel/server/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/os',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/debug',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/os',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/system-z/7/s390x/debug',
      'content/fastrack/rhel/system-z/7/s390x/optional/debug',
      'content/fastrack/rhel/system-z/7/s390x/optional/os',
      'content/fastrack/rhel/system-z/7/s390x/optional/source/SRPMS',
      'content/fastrack/rhel/system-z/7/s390x/os',
      'content/fastrack/rhel/system-z/7/s390x/source/SRPMS',
      'content/fastrack/rhel/workstation/7/x86_64/debug',
      'content/fastrack/rhel/workstation/7/x86_64/optional/debug',
      'content/fastrack/rhel/workstation/7/x86_64/optional/os',
      'content/fastrack/rhel/workstation/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/workstation/7/x86_64/os',
      'content/fastrack/rhel/workstation/7/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-3.10.0-1127.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'bpftool-3.10.0-1127.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'bpftool-3.10.0-1127.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'bpftool-3.10.0-1127.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-3.10.0-1127.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-3.10.0-1127.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-3.10.0-1127.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-3.10.0-1127.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-abi-whitelists-3.10.0-1127.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-bootwrapper-3.10.0-1127.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-bootwrapper-3.10.0-1127.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-1127.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-1127.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-1127.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-1127.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-1127.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-1127.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-1127.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-1127.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-1127.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-1127.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-1127.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-1127.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-1127.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-1127.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-1127.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-1127.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-3.10.0-1127.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-devel-3.10.0-1127.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-3.10.0-1127.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-3.10.0-1127.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-3.10.0-1127.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-3.10.0-1127.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-3.10.0-1127.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-3.10.0-1127.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-3.10.0-1127.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-3.10.0-1127.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-3.10.0-1127.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-1127.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-1127.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-1127.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-1127.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-1127.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-1127.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-1127.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-1127.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-whitelists / kernel-bootwrapper / etc');
}
