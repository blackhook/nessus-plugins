#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124822);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2017-12190",
    "CVE-2017-12192",
    "CVE-2017-12193",
    "CVE-2017-14106",
    "CVE-2017-14140",
    "CVE-2017-14489",
    "CVE-2017-14991",
    "CVE-2017-15102",
    "CVE-2017-15115",
    "CVE-2017-15129",
    "CVE-2017-15265",
    "CVE-2017-15274",
    "CVE-2017-15299",
    "CVE-2017-15649",
    "CVE-2017-16525",
    "CVE-2017-16526",
    "CVE-2017-16527",
    "CVE-2017-16528",
    "CVE-2017-16529",
    "CVE-2017-16530",
    "CVE-2017-16531",
    "CVE-2017-16532"
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : kernel (EulerOS-SA-2019-1499)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - It was found that in the Linux kernel through
    v4.14-rc5, bio_map_user_iov() and bio_unmap_user() in
    'block/bio.c' do unbalanced pages refcounting if IO
    vector has small consecutive buffers belonging to the
    same page. bio_add_pc_page() merges them into one, but
    the page reference is never dropped, causing a memory
    leak and possible system lockup due to out-of-memory
    condition.(CVE-2017-12190)

  - A vulnerability was found in the Key Management sub
    component of the Linux kernel, where when trying to
    issue a KEYTCL_READ on a negative key would lead to a
    NULL pointer dereference. A local attacker could use
    this flaw to crash the kernel.(CVE-2017-12192)

  - A flaw was found in the Linux kernel's implementation
    of associative arrays introduced in 3.13. This
    functionality was backported to the 3.10 kernels in Red
    Hat Enterprise Linux 7. The flaw involved a null
    pointer dereference in assoc_array_apply_edit() due to
    incorrect node-splitting in assoc_array implementation.
    This affects the keyring key type and thus key addition
    and link creation operations may cause the kernel to
    panic.(CVE-2017-12193)

  - A divide-by-zero vulnerability was found in the
    __tcp_select_window function in the Linux kernel. This
    can result in a kernel panic causing a local denial of
    service.(CVE-2017-14106)

  - The move_pages system call in mm/migrate.c in the Linux
    kernel doesn't check the effective uid of the target
    process. This enables a local attacker to learn the
    memory layout of a setuid executable allowing
    mitigation of ASLR.(CVE-2017-14140)

  - The iscsi_if_rx() function in
    'drivers/scsi/scsi_transport_iscsi.c' in the Linux
    kernel from v2.6.24-rc1 through 4.13.2 allows local
    users to cause a denial of service (a system panic) by
    making a number of certain syscalls by leveraging
    incorrect length validation in the kernel
    code.(CVE-2017-14489)

  - The sg_ioctl() function in 'drivers/scsi/sg.c' in the
    Linux kernel, from version 4.12-rc1 to 4.14-rc2, allows
    local users to obtain sensitive information from
    uninitialized kernel heap-memory locations via an
    SG_GET_REQUEST_TABLE ioctl call for
    '/dev/sg0'.(CVE-2017-14991)

  - The tower_probe function in
    drivers/usb/misc/legousbtower.c in the Linux kernel
    before 4.8.1 allows local users (who are physically
    proximate for inserting a crafted USB device) to gain
    privileges by leveraging a write-what-where condition
    that occurs after a race condition and a NULL pointer
    dereference.(CVE-2017-15102)

  - A vulnerability was found in the Linux kernel when
    peeling off an association to the socket in another
    network namespace. All transports in this association
    are not to be rehashed and keep using the old key in
    hashtable, thus removing transports from hashtable when
    closing the socket, all transports are being freed.
    Later on a use-after-free issue could be caused when
    looking up an association and dereferencing the
    transports.(CVE-2017-15115)

  - A use-after-free vulnerability was found in a network
    namespaces code affecting the Linux kernel since
    v4.0-rc1 through v4.15-rc5. The function
    get_net_ns_by_id() does not check for the net::count
    value after it has found a peer network in netns_ids
    idr which could lead to double free and memory
    corruption. This vulnerability could allow an
    unprivileged local user to induce kernel memory
    corruption on the system, leading to a crash. Due to
    the nature of the flaw, privilege escalation cannot be
    fully ruled out, although it is thought to be
    unlikely.(CVE-2017-15129)

  - A use-after-free vulnerability was found when issuing
    an ioctl to a sound device. This could allow a user to
    exploit a race condition and create memory corruption
    or possibly privilege escalation.(CVE-2017-15265)

  - A flaw was found in the implementation of associative
    arrays where the add_key systemcall and KEYCTL_UPDATE
    operations allowed for a NULL payload with a nonzero
    length. When accessing the payload within this length
    parameters value, an unprivileged user could trivially
    cause a NULL pointer dereference (kernel
    oops).(CVE-2017-15274)

  - A vulnerability was found in the key management
    subsystem of the Linux kernel. An update on an
    uninstantiated key could cause a kernel panic, leading
    to denial of service (DoS).(CVE-2017-15299)

  - It was found that fanout_add() in
    'net/packet/af_packet.c' in the Linux kernel, before
    version 4.13.6, allows local users to gain privileges
    via crafted system calls that trigger mishandling of
    packet_fanout data structures, because of a race
    condition (involving fanout_add and packet_do_bind)
    that leads to a use-after-free bug.(CVE-2017-15649)

  - The usb_serial_console_disconnect function in
    drivers/usb/serial/console.c in the Linux kernel,
    before 4.13.8, allows local users to cause a denial of
    service (use-after-free and system crash) or possibly
    have unspecified other impact via a crafted USB device,
    related to disconnection and failed
    setup.(CVE-2017-16525)

  - The drivers/uwb/uwbd.c in the Linux kernel, before
    4.13.6, allows local users to cause a denial of service
    (general protection fault and system crash) or possibly
    have unspecified other impact via a crafted USB
    device.(CVE-2017-16526)

  - The sound/usb/mixer.c in the Linux kernel, before
    4.13.8, allows local users to cause a denial of service
    (snd_usb_mixer_interrupt use-after-free and system
    crash) or possibly have unspecified other impact via a
    crafted USB device.(CVE-2017-16527)

  - The sound/core/seq_device.c in the Linux kernel, before
    4.13.4, allows local users to cause a denial of service
    (snd_rawmidi_dev_seq_free use-after-free and system
    crash) or possibly have unspecified other impact via a
    crafted USB device.(CVE-2017-16528)

  - The snd_usb_create_streams function in sound/usb/card.c
    in the Linux kernel, before 4.13.6, allows local users
    to cause a denial of service (out-of-bounds read and
    system crash) or possibly have unspecified other impact
    via a crafted USB device.(CVE-2017-16529)

  - The uas driver in the Linux kernel before 4.13.6 allows
    local users to cause a denial of service (out-of-bounds
    read and system crash), or possibly have unspecified
    other impacts via a crafted USB device, related to
    drivers/usb/storage/uas-detect.h and
    drivers/usb/storage/uas.c.(CVE-2017-16530)

  - The function drivers/usb/core/config.c in the Linux
    kernel, allows local users to cause a denial of service
    (out-of-bounds read and system crash) or possibly have
    unspecified other impact via a crafted USB device,
    related to the USB_DT_INTERFACE_ASSOCIATION
    descriptor.(CVE-2017-16531)

  - The get_endpoints function in
    drivers/usb/misc/usbtest.c in the Linux kernel through
    4.13.11 allows local users to cause a denial of service
    (NULL pointer dereference and system crash) or possibly
    have unspecified other impact via a crafted USB
    device.(CVE-2017-16532)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1499
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95557cab");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-16532");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-16526");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.6_42",
        "kernel-devel-3.10.0-862.14.1.6_42",
        "kernel-headers-3.10.0-862.14.1.6_42",
        "kernel-tools-3.10.0-862.14.1.6_42",
        "kernel-tools-libs-3.10.0-862.14.1.6_42",
        "kernel-tools-libs-devel-3.10.0-862.14.1.6_42",
        "perf-3.10.0-862.14.1.6_42",
        "python-perf-3.10.0-862.14.1.6_42"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
