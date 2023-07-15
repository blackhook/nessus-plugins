#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2020:14578-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150656);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/10");

  script_cve_id(
    "CVE-2020-29130",
    "CVE-2020-29480",
    "CVE-2020-29481",
    "CVE-2020-29483",
    "CVE-2020-29484",
    "CVE-2020-29566",
    "CVE-2020-29570",
    "CVE-2020-29571"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2020:14578-1");
  script_xref(name:"IAVB", value:"2020-B-0077-S");

  script_name(english:"SUSE SLES11 Security Update : xen (SUSE-SU-2020:14578-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2020:14578-1 advisory.

  - slirp.c in libslirp through 4.3.1 has a buffer over-read because it tries to read a certain amount of
    header data even if that exceeds the total packet length. (CVE-2020-29130)

  - An issue was discovered in Xen through 4.14.x. Neither xenstore implementation does any permission checks
    when reporting a xenstore watch event. A guest administrator can watch the root xenstored node, which will
    cause notifications for every created, modified, and deleted key. A guest administrator can also use the
    special watches, which will cause a notification every time a domain is created and destroyed. Data may
    include: number, type, and domids of other VMs; existence and domids of driver domains; numbers of virtual
    interfaces, block devices, vcpus; existence of virtual framebuffers and their backend style (e.g.,
    existence of VNC service); Xen VM UUIDs for other domains; timing information about domain creation and
    device setup; and some hints at the backend provisioning of VMs and their devices. The watch events do not
    contain values stored in xenstore, only key names. A guest administrator can observe non-sensitive domain
    and device lifecycle events relating to other guests. This information allows some insight into overall
    system configuration (including the number and general nature of other guests), and configuration of other
    guests (including the number and general nature of other guests' devices). This information might be
    commercially interesting or might make other attacks easier. There is not believed to be exposure of
    sensitive data. Specifically, there is no exposure of VNC passwords, port numbers, pathnames in host and
    guest filesystems, cryptographic keys, or within-guest data. (CVE-2020-29480)

  - An issue was discovered in Xen through 4.14.x. Access rights of Xenstore nodes are per domid.
    Unfortunately, existing granted access rights are not removed when a domain is being destroyed. This means
    that a new domain created with the same domid will inherit the access rights to Xenstore nodes from the
    previous domain(s) with the same domid. Because all Xenstore entries of a guest below
    /local/domain/ are being deleted by Xen tools when a guest is destroyed, only Xenstore entries of
    other guests still running are affected. For example, a newly created guest domain might be able to read
    sensitive information that had belonged to a previously existing guest domain. Both Xenstore
    implementations (C and Ocaml) are vulnerable. (CVE-2020-29481)

  - An issue was discovered in Xen through 4.14.x. Xenstored and guests communicate via a shared memory page
    using a specific protocol. When a guest violates this protocol, xenstored will drop the connection to that
    guest. Unfortunately, this is done by just removing the guest from xenstored's internal management,
    resulting in the same actions as if the guest had been destroyed, including sending an @releaseDomain
    event. @releaseDomain events do not say that the guest has been removed. All watchers of this event must
    look at the states of all guests to find the guest that has been removed. When an @releaseDomain is
    generated due to a domain xenstored protocol violation, because the guest is still running, the watchers
    will not react. Later, when the guest is actually destroyed, xenstored will no longer have it stored in
    its internal data base, so no further @releaseDomain event will be sent. This can lead to a zombie domain;
    memory mappings of that guest's memory will not be removed, due to the missing event. This zombie domain
    will be cleaned up only after another domain is destroyed, as that will trigger another @releaseDomain
    event. If the device model of the guest that violated the Xenstore protocol is running in a stub-domain, a
    use-after-free case could happen in xenstored, after having removed the guest from its internal data base,
    possibly resulting in a crash of xenstored. A malicious guest can block resources of the host for a period
    after its own death. Guests with a stub domain device model can eventually crash xenstored, resulting in a
    more serious denial of service (the prevention of any further domain management operations). Only the C
    variant of Xenstore is affected; the Ocaml variant is not affected. Only HVM guests with a stubdom device
    model can cause a serious DoS. (CVE-2020-29483)

  - An issue was discovered in Xen through 4.14.x. When a Xenstore watch fires, the xenstore client that
    registered the watch will receive a Xenstore message containing the path of the modified Xenstore entry
    that triggered the watch, and the tag that was specified when registering the watch. Any communication
    with xenstored is done via Xenstore messages, consisting of a message header and the payload. The payload
    length is limited to 4096 bytes. Any request to xenstored resulting in a response with a payload longer
    than 4096 bytes will result in an error. When registering a watch, the payload length limit applies to the
    combined length of the watched path and the specified tag. Because watches for a specific path are also
    triggered for all nodes below that path, the payload of a watch event message can be longer than the
    payload needed to register the watch. A malicious guest that registers a watch using a very large tag
    (i.e., with a registration operation payload length close to the 4096 byte limit) can cause the generation
    of watch events with a payload length larger than 4096 bytes, by writing to Xenstore entries below the
    watched path. This will result in an error condition in xenstored. This error can result in a NULL pointer
    dereference, leading to a crash of xenstored. A malicious guest administrator can cause xenstored to
    crash, leading to a denial of service. Following a xenstored crash, domains may continue to run, but
    management operations will be impossible. Only C xenstored is affected, oxenstored is not affected.
    (CVE-2020-29484)

  - An issue was discovered in Xen through 4.14.x. When they require assistance from the device model, x86 HVM
    guests must be temporarily de-scheduled. The device model will signal Xen when it has completed its
    operation, via an event channel, so that the relevant vCPU is rescheduled. If the device model were to
    signal Xen without having actually completed the operation, the de-schedule / re-schedule cycle would
    repeat. If, in addition, Xen is resignalled very quickly, the re-schedule may occur before the de-schedule
    was fully complete, triggering a shortcut. This potentially repeating process uses ordinary recursive
    function calls, and thus could result in a stack overflow. A malicious or buggy stubdomain serving a HVM
    guest can cause Xen to crash, resulting in a Denial of Service (DoS) to the entire host. Only x86 systems
    are affected. Arm systems are not affected. Only x86 stubdomains serving HVM guests can exploit the
    vulnerability. (CVE-2020-29566)

  - An issue was discovered in Xen through 4.14.x. Recording of the per-vCPU control block mapping maintained
    by Xen and that of pointers into the control block is reversed. The consumer assumes, seeing the former
    initialized, that the latter are also ready for use. Malicious or buggy guest kernels can mount a Denial
    of Service (DoS) attack affecting the entire system. (CVE-2020-29570)

  - An issue was discovered in Xen through 4.14.x. A bounds check common to most operation time functions
    specific to FIFO event channels depends on the CPU observing consistent state. While the producer side
    uses appropriately ordered writes, the consumer side isn't protected against re-ordered reads, and may
    hence end up de-referencing a NULL pointer. Malicious or buggy guest kernels can mount a Denial of Service
    (DoS) attack affecting the entire system. Only Arm systems may be vulnerable. Whether a system is
    vulnerable depends on the specific CPU. x86 systems are not vulnerable. (CVE-2020-29571)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179477");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179498");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179516");
  # https://lists.suse.com/pipermail/sle-security-updates/2020-December/008079.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18028347");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29130");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29480");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29481");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29483");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29484");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29566");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29570");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29571");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-29481");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

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
    {'reference':'xen-4.4.4_48-61.61', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-doc-html-4.4.4_48-61.61', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-kmp-default-4.4.4_48_3.0.101_108.117-61.61', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-kmp-default-4.4.4_48_3.0.101_108.117-61.61', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-kmp-pae-4.4.4_48_3.0.101_108.117-61.61', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-libs-32bit-4.4.4_48-61.61', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-libs-4.4.4_48-61.61', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-libs-4.4.4_48-61.61', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-tools-4.4.4_48-61.61', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-tools-domU-4.4.4_48-61.61', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-tools-domU-4.4.4_48-61.61', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-4.4.4_48-61.61', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-doc-html-4.4.4_48-61.61', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-kmp-default-4.4.4_48_3.0.101_108.117-61.61', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-kmp-default-4.4.4_48_3.0.101_108.117-61.61', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-kmp-pae-4.4.4_48_3.0.101_108.117-61.61', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-libs-32bit-4.4.4_48-61.61', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-libs-4.4.4_48-61.61', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-libs-4.4.4_48-61.61', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-tools-4.4.4_48-61.61', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-tools-domU-4.4.4_48-61.61', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-tools-domU-4.4.4_48-61.61', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xen / xen-doc-html / xen-kmp-default / xen-kmp-pae / xen-libs / etc');
}
