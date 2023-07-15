#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2020:14354-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150557);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/10");

  script_cve_id(
    "CVE-2019-12456",
    "CVE-2019-14896",
    "CVE-2019-14897",
    "CVE-2019-15213",
    "CVE-2019-15916",
    "CVE-2019-18660",
    "CVE-2019-18675",
    "CVE-2019-19066",
    "CVE-2019-19073",
    "CVE-2019-19074",
    "CVE-2019-19227",
    "CVE-2019-19523",
    "CVE-2019-19524",
    "CVE-2019-19527",
    "CVE-2019-19530",
    "CVE-2019-19531",
    "CVE-2019-19532",
    "CVE-2019-19537",
    "CVE-2019-19768",
    "CVE-2019-19965",
    "CVE-2019-19966",
    "CVE-2019-20096",
    "CVE-2020-8647",
    "CVE-2020-8648",
    "CVE-2020-8649",
    "CVE-2020-9383",
    "CVE-2020-10942",
    "CVE-2020-11608"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2020:14354-1");

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2020:14354-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2020:14354-1 advisory.

  - ** DISPUTED ** An issue was discovered in the MPT3COMMAND case in _ctl_ioctl_main in
    drivers/scsi/mpt3sas/mpt3sas_ctl.c in the Linux kernel through 5.1.5. It allows local users to cause a
    denial of service or possibly have unspecified other impact by changing the value of ioc_number between
    two kernel reads of that value, aka a double fetch vulnerability. NOTE: a third party reports that this
    is unexploitable because the doubly fetched value is not used. (CVE-2019-12456)

  - A heap-based buffer overflow vulnerability was found in the Linux kernel, version kernel-2.6.32, in
    Marvell WiFi chip driver. A remote attacker could cause a denial of service (system crash) or, possibly
    execute arbitrary code, when the lbs_ibss_join_existing function is called after a STA connects to an AP.
    (CVE-2019-14896)

  - A stack-based buffer overflow was found in the Linux kernel, version kernel-2.6.32, in Marvell WiFi chip
    driver. An attacker is able to cause a denial of service (system crash) or, possibly execute arbitrary
    code, when a STA works in IBSS mode (allows connecting stations together without the use of an AP) and
    connects to another STA. (CVE-2019-14897)

  - An issue was discovered in the Linux kernel before 5.2.3. There is a use-after-free caused by a malicious
    USB device in the drivers/media/usb/dvb-usb/dvb-usb-init.c driver. (CVE-2019-15213)

  - An issue was discovered in the Linux kernel before 5.0.1. There is a memory leak in
    register_queue_kobjects() in net/core/net-sysfs.c, which will cause denial of service. (CVE-2019-15916)

  - The Linux kernel before 5.4.1 on powerpc allows Information Exposure because the Spectre-RSB mitigation is
    not in place for all applicable CPUs, aka CID-39e72bf96f58. This is related to
    arch/powerpc/kernel/entry_64.S and arch/powerpc/kernel/security.c. (CVE-2019-18660)

  - The Linux kernel through 5.3.13 has a start_offset+size Integer Overflow in cpia2_remap_buffer in
    drivers/media/usb/cpia2/cpia2_core.c because cpia2 has its own mmap implementation. This allows local
    users (with /dev/video0 access) to obtain read and write permissions on kernel physical pages, which can
    possibly result in a privilege escalation. (CVE-2019-18675)

  - A memory leak in the bfad_im_get_stats() function in drivers/scsi/bfa/bfad_attr.c in the Linux kernel
    through 5.3.11 allows attackers to cause a denial of service (memory consumption) by triggering
    bfa_port_get_stats() failures, aka CID-0e62395da2bd. (CVE-2019-19066)

  - Memory leaks in drivers/net/wireless/ath/ath9k/htc_hst.c in the Linux kernel through 5.3.11 allow
    attackers to cause a denial of service (memory consumption) by triggering wait_for_completion_timeout()
    failures. This affects the htc_config_pipe_credits() function, the htc_setup_complete() function, and the
    htc_connect_service() function, aka CID-853acf7caf10. (CVE-2019-19073)

  - A memory leak in the ath9k_wmi_cmd() function in drivers/net/wireless/ath/ath9k/wmi.c in the Linux kernel
    through 5.3.11 allows attackers to cause a denial of service (memory consumption), aka CID-728c1e2a05e4.
    (CVE-2019-19074)

  - In the AppleTalk subsystem in the Linux kernel before 5.1, there is a potential NULL pointer dereference
    because register_snap_client may return NULL. This will lead to denial of service in net/appletalk/aarp.c
    and net/appletalk/ddp.c, as demonstrated by unregister_snap_client, aka CID-9804501fa122. (CVE-2019-19227)

  - In the Linux kernel before 5.3.7, there is a use-after-free bug that can be caused by a malicious USB
    device in the drivers/usb/misc/adutux.c driver, aka CID-44efc269db79. (CVE-2019-19523)

  - In the Linux kernel before 5.3.12, there is a use-after-free bug that can be caused by a malicious USB
    device in the drivers/input/ff-memless.c driver, aka CID-fa3a5a1880c9. (CVE-2019-19524)

  - In the Linux kernel before 5.2.10, there is a use-after-free bug that can be caused by a malicious USB
    device in the drivers/hid/usbhid/hiddev.c driver, aka CID-9c09b214f30e. (CVE-2019-19527)

  - In the Linux kernel before 5.2.10, there is a use-after-free bug that can be caused by a malicious USB
    device in the drivers/usb/class/cdc-acm.c driver, aka CID-c52873e5a1ef. (CVE-2019-19530)

  - In the Linux kernel before 5.2.9, there is a use-after-free bug that can be caused by a malicious USB
    device in the drivers/usb/misc/yurex.c driver, aka CID-fc05481b2fca. (CVE-2019-19531)

  - In the Linux kernel before 5.3.9, there are multiple out-of-bounds write bugs that can be caused by a
    malicious USB device in the Linux kernel HID drivers, aka CID-d9d4b1e46d95. This affects drivers/hid/hid-
    axff.c, drivers/hid/hid-dr.c, drivers/hid/hid-emsff.c, drivers/hid/hid-gaff.c, drivers/hid/hid-holtekff.c,
    drivers/hid/hid-lg2ff.c, drivers/hid/hid-lg3ff.c, drivers/hid/hid-lg4ff.c, drivers/hid/hid-lgff.c,
    drivers/hid/hid-logitech-hidpp.c, drivers/hid/hid-microsoft.c, drivers/hid/hid-sony.c, drivers/hid/hid-
    tmff.c, and drivers/hid/hid-zpff.c. (CVE-2019-19532)

  - In the Linux kernel before 5.2.10, there is a race condition bug that can be caused by a malicious USB
    device in the USB character device driver layer, aka CID-303911cfc5b9. This affects
    drivers/usb/core/file.c. (CVE-2019-19537)

  - In the Linux kernel 5.4.0-rc2, there is a use-after-free (read) in the __blk_add_trace function in
    kernel/trace/blktrace.c (which is used to fill out a blk_io_trace structure and place it in a per-cpu sub-
    buffer). (CVE-2019-19768)

  - In the Linux kernel through 5.4.6, there is a NULL pointer dereference in
    drivers/scsi/libsas/sas_discover.c because of mishandling of port disconnection during discovery, related
    to a PHY down race condition, aka CID-f70267f379b5. (CVE-2019-19965)

  - In the Linux kernel before 5.1.6, there is a use-after-free in cpia2_exit() in
    drivers/media/usb/cpia2/cpia2_v4l.c that will cause denial of service, aka CID-dea37a972655.
    (CVE-2019-19966)

  - In the Linux kernel before 5.1, there is a memory leak in __feat_register_sp() in net/dccp/feat.c, which
    may cause denial of service, aka CID-1d3ff0950e2b. (CVE-2019-20096)

  - In the Linux kernel before 5.5.8, get_raw_socket in drivers/vhost/net.c lacks validation of an sk_family
    field, which might allow attackers to trigger kernel stack corruption via crafted system calls.
    (CVE-2020-10942)

  - An issue was discovered in the Linux kernel before 5.6.1. drivers/media/usb/gspca/ov519.c allows NULL
    pointer dereferences in ov511_mode_init_regs and ov518_mode_init_regs when there are zero endpoints, aka
    CID-998912346c0d. (CVE-2020-11608)

  - There is a use-after-free vulnerability in the Linux kernel through 5.5.2 in the vc_do_resize function in
    drivers/tty/vt/vt.c. (CVE-2020-8647)

  - There is a use-after-free vulnerability in the Linux kernel through 5.5.2 in the n_tty_receive_buf_common
    function in drivers/tty/n_tty.c. (CVE-2020-8648)

  - There is a use-after-free vulnerability in the Linux kernel through 5.5.2 in the vgacon_invert_region
    function in drivers/video/console/vgacon.c. (CVE-2020-8649)

  - An issue was discovered in the Linux kernel 3.16 through 5.5.6. set_fdc in drivers/block/floppy.c leads to
    a wait_til_ready out-of-bounds read because the FDC index is not checked for errors before assigning it,
    aka CID-2e90ca68b0d2. (CVE-2020-9383)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1012382");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1091041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1105327");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1131107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1136471");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1136922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1146519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1146544");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1146612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1148871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1149448");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156652");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1157038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1157070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1157143");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1157155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1157157");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1157303");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1157344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1157678");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1157804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1157923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158381");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158824");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158900");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1159285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1159841");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1159908");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1159911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1161358");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1162928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1162929");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1162931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1164078");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1165111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1165985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1168075");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1168829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1168854");
  # https://lists.suse.com/pipermail/sle-security-updates/2020-April/006770.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc6cc79a");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-12456");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-14896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-14897");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15213");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15916");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-18660");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-18675");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19066");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19073");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19074");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19227");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19523");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19524");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19527");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19530");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19531");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19532");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19537");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19768");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19965");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19966");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-20096");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10942");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-11608");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8647");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8648");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8649");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-9383");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14896");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigmem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigmem-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigmem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ppc64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ppc64-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ppc64-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES11', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);

pkgs = [
    {'reference':'kernel-default-3.0.101-108.111', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-default-base-3.0.101-108.111', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-default-devel-3.0.101-108.111', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-default-man-3.0.101-108.111', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-ec2-3.0.101-108.111', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-ec2-3.0.101-108.111', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-ec2-base-3.0.101-108.111', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-ec2-base-3.0.101-108.111', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-ec2-devel-3.0.101-108.111', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-ec2-devel-3.0.101-108.111', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-pae-3.0.101-108.111', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-pae-base-3.0.101-108.111', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-pae-devel-3.0.101-108.111', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-source-3.0.101-108.111', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-syms-3.0.101-108.111', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-trace-3.0.101-108.111', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-trace-base-3.0.101-108.111', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-trace-devel-3.0.101-108.111', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-xen-3.0.101-108.111', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-xen-3.0.101-108.111', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-xen-base-3.0.101-108.111', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-xen-base-3.0.101-108.111', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-xen-devel-3.0.101-108.111', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-xen-devel-3.0.101-108.111', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-default-3.0.101-108.111', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-default-base-3.0.101-108.111', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-default-devel-3.0.101-108.111', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-default-man-3.0.101-108.111', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-3.0.101-108.111', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-3.0.101-108.111', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-base-3.0.101-108.111', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-base-3.0.101-108.111', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-devel-3.0.101-108.111', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-devel-3.0.101-108.111', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-pae-3.0.101-108.111', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-pae-base-3.0.101-108.111', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-pae-devel-3.0.101-108.111', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-source-3.0.101-108.111', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-syms-3.0.101-108.111', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-trace-3.0.101-108.111', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-trace-base-3.0.101-108.111', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-trace-devel-3.0.101-108.111', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-3.0.101-108.111', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-3.0.101-108.111', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-base-3.0.101-108.111', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-base-3.0.101-108.111', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-devel-3.0.101-108.111', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-devel-3.0.101-108.111', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  exists_check = NULL;
  rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release && exists_check) {
    if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
  else if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-default / kernel-default-base / kernel-default-devel / etc');
}
