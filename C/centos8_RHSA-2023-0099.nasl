#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2023:0099. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(169972);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id("CVE-2022-4144");
  script_xref(name:"RHSA", value:"2023:0099");

  script_name(english:"CentOS 8 : virt:rhel and virt-devel:rhel (CESA-2023:0099)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
CESA-2023:0099 advisory.

  - QEMU: QXL: qxl_phys2virt unsafe address translation can lead to out-of-bounds read (CVE-2022-4144)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:0099");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4144");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-appliance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-gfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-inspect-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-java-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-man-pages-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-man-pages-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-rescue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-rsync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-tools-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-xfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libnbd-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libnbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtpms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtpms-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:lua-guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nbdfuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-libnbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-Sys-Guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seavgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:supermin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:supermin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:swtpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:swtpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:swtpm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:swtpm-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:swtpm-tools-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:virt-dib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:virt-v2v");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:virt-v2v-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:virt-v2v-man-pages-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:virt-v2v-man-pages-uk");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS 8-Stream');
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/virt-devel');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module virt-devel:rhel');
if ('rhel' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module virt-devel:' + module_ver);

var appstreams = {
    'virt-devel:rhel': [
      {'reference':'libguestfs-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-appliance-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-appliance-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-bash-completion-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-bash-completion-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-devel-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-devel-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-gfs2-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-gfs2-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-gobject-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-gobject-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-gobject-devel-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-gobject-devel-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-inspect-icons-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-inspect-icons-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-java-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-java-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-java-devel-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-java-devel-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-javadoc-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-javadoc-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-man-pages-ja-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-man-pages-ja-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-man-pages-uk-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-man-pages-uk-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-rescue-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-rescue-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-rsync-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-rsync-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-tools-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-tools-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-tools-c-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-tools-c-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-xfs-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-xfs-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-1.6.0-5.module_el8.7.0+1140+ff0772f9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-1.6.0-5.module_el8.7.0+1140+ff0772f9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-bash-completion-1.6.0-5.module_el8.7.0+1140+ff0772f9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-bash-completion-1.6.0-5.module_el8.7.0+1140+ff0772f9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-devel-1.6.0-5.module_el8.7.0+1140+ff0772f9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-devel-1.6.0-5.module_el8.7.0+1140+ff0772f9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libtpms-0.9.1-1.20211126git1ff6fe1f43.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libtpms-0.9.1-1.20211126git1ff6fe1f43.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libtpms-devel-0.9.1-1.20211126git1ff6fe1f43.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libtpms-devel-0.9.1-1.20211126git1ff6fe1f43.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'lua-guestfs-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'lua-guestfs-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdfuse-1.6.0-5.module_el8.7.0+1140+ff0772f9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdfuse-1.6.0-5.module_el8.7.0+1140+ff0772f9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libguestfs-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libguestfs-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libguestfs-devel-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libguestfs-devel-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libnbd-1.6.0-5.module_el8.7.0+1140+ff0772f9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libnbd-1.6.0-5.module_el8.7.0+1140+ff0772f9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libnbd-devel-1.6.0-5.module_el8.7.0+1140+ff0772f9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libnbd-devel-1.6.0-5.module_el8.7.0+1140+ff0772f9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sys-Guestfs-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sys-Guestfs-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libguestfs-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libguestfs-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libnbd-1.6.0-5.module_el8.7.0+1140+ff0772f9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libnbd-1.6.0-5.module_el8.7.0+1140+ff0772f9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libvirt-8.0.0-2.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libvirt-8.0.0-2.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libguestfs-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libguestfs-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seabios-1.16.0-3.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seabios-1.16.0-3.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seabios-bin-1.16.0-3.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seabios-bin-1.16.0-3.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seavgabios-bin-1.16.0-3.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seavgabios-bin-1.16.0-3.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'supermin-5.2.1-2.module_el8.7.0+1140+ff0772f9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'supermin-5.2.1-2.module_el8.7.0+1140+ff0772f9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'supermin-devel-5.2.1-2.module_el8.7.0+1140+ff0772f9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'supermin-devel-5.2.1-2.module_el8.7.0+1140+ff0772f9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-0.7.0-4.20211109gitb79fd91.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-0.7.0-4.20211109gitb79fd91.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-devel-0.7.0-4.20211109gitb79fd91.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-devel-0.7.0-4.20211109gitb79fd91.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-libs-0.7.0-4.20211109gitb79fd91.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-libs-0.7.0-4.20211109gitb79fd91.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-tools-0.7.0-4.20211109gitb79fd91.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-tools-0.7.0-4.20211109gitb79fd91.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-tools-pkcs11-0.7.0-4.20211109gitb79fd91.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-tools-pkcs11-0.7.0-4.20211109gitb79fd91.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'virt-dib-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'virt-dib-1.44.0-9.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'virt-v2v-1.42.0-21.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'virt-v2v-1.42.0-21.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'virt-v2v-bash-completion-1.42.0-21.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'virt-v2v-bash-completion-1.42.0-21.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'virt-v2v-man-pages-ja-1.42.0-21.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'virt-v2v-man-pages-ja-1.42.0-21.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'virt-v2v-man-pages-uk-1.42.0-21.module_el8.7.0+1218+f626c2ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'virt-v2v-man-pages-uk-1.42.0-21.module_el8.7.0+1218+f626c2ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
appstreams_found = 0;
foreach module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && _release) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module virt-devel:rhel');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libguestfs / libguestfs-appliance / libguestfs-bash-completion / etc');
}
