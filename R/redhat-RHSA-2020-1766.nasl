##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:1766. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(136113);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id(
    "CVE-2018-20337",
    "CVE-2019-3825",
    "CVE-2019-12447",
    "CVE-2019-12448",
    "CVE-2019-12449"
  );
  script_bugtraq_id(107124, 109289);
  script_xref(name:"RHSA", value:"2020:1766");

  script_name(english:"RHEL 8 : GNOME (RHSA-2020:1766)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:1766 advisory.

  - LibRaw: stack-based buffer overflow in the parse_makernote function of dcraw_common.cpp (CVE-2018-20337)

  - gvfs: mishandling of file ownership in daemon/gvfsbackendadmin.c (CVE-2019-12447)

  - gvfs: race condition in daemon/gvfsbackendadmin.c due to admin backend not implementing
    query_info_on_read/write (CVE-2019-12448)

  - gvfs: mishandling of file's user and group ownership in daemon/gvfsbackendadmin.c due to unavailability of
    root privileges (CVE-2019-12449)

  - gdm: lock screen bypass when timed login is enabled (CVE-2019-3825)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-20337");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-3825");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-12447");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-12448");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-12449");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:1766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1661555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1672825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1728562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1728564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1728567");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3825");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-20337");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(121, 282, 287, 364);

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:LibRaw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:LibRaw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:accountsservice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:accountsservice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:accountsservice-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:appstream-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:baobab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:clutter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:clutter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:clutter-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evince-browser-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evince-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evince-nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gjs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-boxes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-control-center");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-control-center-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-menus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-menus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-online-accounts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-online-accounts-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-remote-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-session-wayland-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-session-xsession");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-settings-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-software");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-software-editor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-terminal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-terminal-nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-tweaks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gsettings-desktop-schemas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gsettings-desktop-schemas-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gtk-update-icon-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gtk3-immodule-xim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-afc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-afp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-archive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-goa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-gphoto2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-mtp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-smb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvncserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvncserver-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxslt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxslt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozjs52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozjs52-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozjs60");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozjs60-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mutter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mutter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nautilus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nautilus-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vala");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vala-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vinagre");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.2/x86_64/appstream/debug',
      'content/aus/rhel8/8.2/x86_64/appstream/os',
      'content/aus/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/aus/rhel8/8.2/x86_64/baseos/debug',
      'content/aus/rhel8/8.2/x86_64/baseos/os',
      'content/aus/rhel8/8.2/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/appstream/debug',
      'content/e4s/rhel8/8.2/ppc64le/appstream/os',
      'content/e4s/rhel8/8.2/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/baseos/debug',
      'content/e4s/rhel8/8.2/ppc64le/baseos/os',
      'content/e4s/rhel8/8.2/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/highavailability/debug',
      'content/e4s/rhel8/8.2/ppc64le/highavailability/os',
      'content/e4s/rhel8/8.2/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/sap-solutions/debug',
      'content/e4s/rhel8/8.2/ppc64le/sap-solutions/os',
      'content/e4s/rhel8/8.2/ppc64le/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/sap/debug',
      'content/e4s/rhel8/8.2/ppc64le/sap/os',
      'content/e4s/rhel8/8.2/ppc64le/sap/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/appstream/debug',
      'content/e4s/rhel8/8.2/x86_64/appstream/os',
      'content/e4s/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/baseos/debug',
      'content/e4s/rhel8/8.2/x86_64/baseos/os',
      'content/e4s/rhel8/8.2/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/highavailability/debug',
      'content/e4s/rhel8/8.2/x86_64/highavailability/os',
      'content/e4s/rhel8/8.2/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/sap-solutions/debug',
      'content/e4s/rhel8/8.2/x86_64/sap-solutions/os',
      'content/e4s/rhel8/8.2/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/sap/debug',
      'content/e4s/rhel8/8.2/x86_64/sap/os',
      'content/e4s/rhel8/8.2/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.2/aarch64/appstream/debug',
      'content/eus/rhel8/8.2/aarch64/appstream/os',
      'content/eus/rhel8/8.2/aarch64/appstream/source/SRPMS',
      'content/eus/rhel8/8.2/aarch64/baseos/debug',
      'content/eus/rhel8/8.2/aarch64/baseos/os',
      'content/eus/rhel8/8.2/aarch64/baseos/source/SRPMS',
      'content/eus/rhel8/8.2/aarch64/codeready-builder/debug',
      'content/eus/rhel8/8.2/aarch64/codeready-builder/os',
      'content/eus/rhel8/8.2/aarch64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.2/aarch64/highavailability/debug',
      'content/eus/rhel8/8.2/aarch64/highavailability/os',
      'content/eus/rhel8/8.2/aarch64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.2/aarch64/supplementary/debug',
      'content/eus/rhel8/8.2/aarch64/supplementary/os',
      'content/eus/rhel8/8.2/aarch64/supplementary/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/appstream/debug',
      'content/eus/rhel8/8.2/ppc64le/appstream/os',
      'content/eus/rhel8/8.2/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/baseos/debug',
      'content/eus/rhel8/8.2/ppc64le/baseos/os',
      'content/eus/rhel8/8.2/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/codeready-builder/debug',
      'content/eus/rhel8/8.2/ppc64le/codeready-builder/os',
      'content/eus/rhel8/8.2/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/highavailability/debug',
      'content/eus/rhel8/8.2/ppc64le/highavailability/os',
      'content/eus/rhel8/8.2/ppc64le/highavailability/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/resilientstorage/debug',
      'content/eus/rhel8/8.2/ppc64le/resilientstorage/os',
      'content/eus/rhel8/8.2/ppc64le/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/sap-solutions/debug',
      'content/eus/rhel8/8.2/ppc64le/sap-solutions/os',
      'content/eus/rhel8/8.2/ppc64le/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/sap/debug',
      'content/eus/rhel8/8.2/ppc64le/sap/os',
      'content/eus/rhel8/8.2/ppc64le/sap/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/supplementary/debug',
      'content/eus/rhel8/8.2/ppc64le/supplementary/os',
      'content/eus/rhel8/8.2/ppc64le/supplementary/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/appstream/debug',
      'content/eus/rhel8/8.2/x86_64/appstream/os',
      'content/eus/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/baseos/debug',
      'content/eus/rhel8/8.2/x86_64/baseos/os',
      'content/eus/rhel8/8.2/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.2/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.2/x86_64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/highavailability/debug',
      'content/eus/rhel8/8.2/x86_64/highavailability/os',
      'content/eus/rhel8/8.2/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/resilientstorage/debug',
      'content/eus/rhel8/8.2/x86_64/resilientstorage/os',
      'content/eus/rhel8/8.2/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/sap-solutions/debug',
      'content/eus/rhel8/8.2/x86_64/sap-solutions/os',
      'content/eus/rhel8/8.2/x86_64/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/sap/debug',
      'content/eus/rhel8/8.2/x86_64/sap/os',
      'content/eus/rhel8/8.2/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/supplementary/debug',
      'content/eus/rhel8/8.2/x86_64/supplementary/os',
      'content/eus/rhel8/8.2/x86_64/supplementary/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/appstream/debug',
      'content/tus/rhel8/8.2/x86_64/appstream/os',
      'content/tus/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/baseos/debug',
      'content/tus/rhel8/8.2/x86_64/baseos/os',
      'content/tus/rhel8/8.2/x86_64/baseos/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/highavailability/debug',
      'content/tus/rhel8/8.2/x86_64/highavailability/os',
      'content/tus/rhel8/8.2/x86_64/highavailability/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/nfv/debug',
      'content/tus/rhel8/8.2/x86_64/nfv/os',
      'content/tus/rhel8/8.2/x86_64/nfv/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/rt/debug',
      'content/tus/rhel8/8.2/x86_64/rt/os',
      'content/tus/rhel8/8.2/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'accountsservice-0.6.50-8.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-0.6.50-8.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-0.6.50-8.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-devel-0.6.50-8.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-devel-0.6.50-8.el8', 'sp':'2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-devel-0.6.50-8.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-devel-0.6.50-8.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-libs-0.6.50-8.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-libs-0.6.50-8.el8', 'sp':'2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-libs-0.6.50-8.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-libs-0.6.50-8.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'appstream-data-8-20191129.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'baobab-3.28.0-4.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clutter-1.26.2-8.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clutter-devel-1.26.2-8.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clutter-doc-1.26.2-8.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-3.28.4-4.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-3.28.4-4.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-3.28.4-4.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-browser-plugin-3.28.4-4.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-browser-plugin-3.28.4-4.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-browser-plugin-3.28.4-4.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-libs-3.28.4-4.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-nautilus-3.28.4-4.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-nautilus-3.28.4-4.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-nautilus-3.28.4-4.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gdm-3.28.3-29.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'gdm-3.28.3-29.el8', 'sp':'2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'gdm-3.28.3-29.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'gdm-3.28.3-29.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'gjs-1.56.2-4.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gjs-devel-1.56.2-4.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-boxes-3.28.5-8.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-control-center-3.28.2-19.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-control-center-3.28.2-19.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-control-center-3.28.2-19.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-control-center-filesystem-3.28.2-19.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-3.13.3-11.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-3.13.3-11.el8', 'sp':'2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-3.13.3-11.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-3.13.3-11.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-devel-3.13.3-11.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-devel-3.13.3-11.el8', 'sp':'2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-devel-3.13.3-11.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-devel-3.13.3-11.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-3.28.2-1.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-3.28.2-1.el8', 'sp':'2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-3.28.2-1.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-3.28.2-1.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-devel-3.28.2-1.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-devel-3.28.2-1.el8', 'sp':'2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-devel-3.28.2-1.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-devel-3.28.2-1.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-remote-desktop-0.1.6-8.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-remote-desktop-0.1.6-8.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-remote-desktop-0.1.6-8.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-3.28.1-8.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-3.28.1-8.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-3.28.1-8.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-wayland-session-3.28.1-8.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-wayland-session-3.28.1-8.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-wayland-session-3.28.1-8.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-xsession-3.28.1-8.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-xsession-3.28.1-8.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-xsession-3.28.1-8.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-settings-daemon-3.32.0-9.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-settings-daemon-3.32.0-9.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-settings-daemon-3.32.0-9.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-shell-3.32.2-14.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-shell-3.32.2-14.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-shell-3.32.2-14.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-software-3.30.6-3.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-software-3.30.6-3.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-software-3.30.6-3.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-software-editor-3.30.6-3.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-software-editor-3.30.6-3.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-software-editor-3.30.6-3.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-terminal-3.28.3-1.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-terminal-3.28.3-1.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-terminal-3.28.3-1.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-terminal-nautilus-3.28.3-1.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-terminal-nautilus-3.28.3-1.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-terminal-nautilus-3.28.3-1.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-tweaks-3.28.1-7.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gsettings-desktop-schemas-3.32.0-4.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gsettings-desktop-schemas-devel-3.32.0-4.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gsettings-desktop-schemas-devel-3.32.0-4.el8', 'sp':'2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gsettings-desktop-schemas-devel-3.32.0-4.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gsettings-desktop-schemas-devel-3.32.0-4.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gtk-update-icon-cache-3.22.30-5.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gtk3-3.22.30-5.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gtk3-devel-3.22.30-5.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gtk3-immodule-xim-3.22.30-5.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-1.36.2-8.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-afc-1.36.2-8.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-afc-1.36.2-8.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-afc-1.36.2-8.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-afp-1.36.2-8.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-afp-1.36.2-8.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-afp-1.36.2-8.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-archive-1.36.2-8.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-archive-1.36.2-8.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-archive-1.36.2-8.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-client-1.36.2-8.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-devel-1.36.2-8.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-fuse-1.36.2-8.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-goa-1.36.2-8.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-goa-1.36.2-8.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-goa-1.36.2-8.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-gphoto2-1.36.2-8.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-mtp-1.36.2-8.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-smb-1.36.2-8.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-1.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-1.el8', 'sp':'2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-1.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-1.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-1.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-1.el8', 'sp':'2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-1.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-1.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvncserver-0.9.11-14.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvncserver-devel-0.9.11-14.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libxslt-1.1.32-4.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libxslt-devel-1.1.32-4.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mozjs52-52.9.0-2.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mozjs52-devel-52.9.0-2.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mozjs60-60.9.0-4.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mozjs60-devel-60.9.0-4.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-3.32.2-34.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-3.32.2-34.el8', 'sp':'2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-3.32.2-34.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-3.32.2-34.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-devel-3.32.2-34.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-devel-3.32.2-34.el8', 'sp':'2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-devel-3.32.2-34.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-devel-3.32.2-34.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-3.28.1-12.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-3.28.1-12.el8', 'sp':'2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-3.28.1-12.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-3.28.1-12.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-devel-3.28.1-12.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-devel-3.28.1-12.el8', 'sp':'2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-devel-3.28.1-12.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-devel-3.28.1-12.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-extensions-3.28.1-12.el8', 'sp':'2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-extensions-3.28.1-12.el8', 'sp':'2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-extensions-3.28.1-12.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-extensions-3.28.1-12.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'vala-0.40.19-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'vala-devel-0.40.19-1.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'vinagre-3.22.0-21.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.4/x86_64/appstream/debug',
      'content/aus/rhel8/8.4/x86_64/appstream/os',
      'content/aus/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/aus/rhel8/8.4/x86_64/baseos/debug',
      'content/aus/rhel8/8.4/x86_64/baseos/os',
      'content/aus/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/appstream/debug',
      'content/e4s/rhel8/8.4/ppc64le/appstream/os',
      'content/e4s/rhel8/8.4/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/baseos/debug',
      'content/e4s/rhel8/8.4/ppc64le/baseos/os',
      'content/e4s/rhel8/8.4/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/highavailability/debug',
      'content/e4s/rhel8/8.4/ppc64le/highavailability/os',
      'content/e4s/rhel8/8.4/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/sap-solutions/debug',
      'content/e4s/rhel8/8.4/ppc64le/sap-solutions/os',
      'content/e4s/rhel8/8.4/ppc64le/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/sap/debug',
      'content/e4s/rhel8/8.4/ppc64le/sap/os',
      'content/e4s/rhel8/8.4/ppc64le/sap/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/appstream/debug',
      'content/e4s/rhel8/8.4/x86_64/appstream/os',
      'content/e4s/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/baseos/debug',
      'content/e4s/rhel8/8.4/x86_64/baseos/os',
      'content/e4s/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/highavailability/debug',
      'content/e4s/rhel8/8.4/x86_64/highavailability/os',
      'content/e4s/rhel8/8.4/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/sap-solutions/debug',
      'content/e4s/rhel8/8.4/x86_64/sap-solutions/os',
      'content/e4s/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/sap/debug',
      'content/e4s/rhel8/8.4/x86_64/sap/os',
      'content/e4s/rhel8/8.4/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.4/aarch64/appstream/debug',
      'content/eus/rhel8/8.4/aarch64/appstream/os',
      'content/eus/rhel8/8.4/aarch64/appstream/source/SRPMS',
      'content/eus/rhel8/8.4/aarch64/baseos/debug',
      'content/eus/rhel8/8.4/aarch64/baseos/os',
      'content/eus/rhel8/8.4/aarch64/baseos/source/SRPMS',
      'content/eus/rhel8/8.4/aarch64/codeready-builder/debug',
      'content/eus/rhel8/8.4/aarch64/codeready-builder/os',
      'content/eus/rhel8/8.4/aarch64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.4/aarch64/highavailability/debug',
      'content/eus/rhel8/8.4/aarch64/highavailability/os',
      'content/eus/rhel8/8.4/aarch64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.4/aarch64/supplementary/debug',
      'content/eus/rhel8/8.4/aarch64/supplementary/os',
      'content/eus/rhel8/8.4/aarch64/supplementary/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/appstream/debug',
      'content/eus/rhel8/8.4/ppc64le/appstream/os',
      'content/eus/rhel8/8.4/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/baseos/debug',
      'content/eus/rhel8/8.4/ppc64le/baseos/os',
      'content/eus/rhel8/8.4/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/codeready-builder/debug',
      'content/eus/rhel8/8.4/ppc64le/codeready-builder/os',
      'content/eus/rhel8/8.4/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/highavailability/debug',
      'content/eus/rhel8/8.4/ppc64le/highavailability/os',
      'content/eus/rhel8/8.4/ppc64le/highavailability/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/resilientstorage/debug',
      'content/eus/rhel8/8.4/ppc64le/resilientstorage/os',
      'content/eus/rhel8/8.4/ppc64le/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/sap-solutions/debug',
      'content/eus/rhel8/8.4/ppc64le/sap-solutions/os',
      'content/eus/rhel8/8.4/ppc64le/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/sap/debug',
      'content/eus/rhel8/8.4/ppc64le/sap/os',
      'content/eus/rhel8/8.4/ppc64le/sap/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/supplementary/debug',
      'content/eus/rhel8/8.4/ppc64le/supplementary/os',
      'content/eus/rhel8/8.4/ppc64le/supplementary/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/appstream/debug',
      'content/eus/rhel8/8.4/x86_64/appstream/os',
      'content/eus/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/baseos/debug',
      'content/eus/rhel8/8.4/x86_64/baseos/os',
      'content/eus/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/highavailability/debug',
      'content/eus/rhel8/8.4/x86_64/highavailability/os',
      'content/eus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/resilientstorage/debug',
      'content/eus/rhel8/8.4/x86_64/resilientstorage/os',
      'content/eus/rhel8/8.4/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/sap-solutions/debug',
      'content/eus/rhel8/8.4/x86_64/sap-solutions/os',
      'content/eus/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/sap/debug',
      'content/eus/rhel8/8.4/x86_64/sap/os',
      'content/eus/rhel8/8.4/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/supplementary/debug',
      'content/eus/rhel8/8.4/x86_64/supplementary/os',
      'content/eus/rhel8/8.4/x86_64/supplementary/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/appstream/debug',
      'content/tus/rhel8/8.4/x86_64/appstream/os',
      'content/tus/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/baseos/debug',
      'content/tus/rhel8/8.4/x86_64/baseos/os',
      'content/tus/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/highavailability/debug',
      'content/tus/rhel8/8.4/x86_64/highavailability/os',
      'content/tus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/nfv/debug',
      'content/tus/rhel8/8.4/x86_64/nfv/os',
      'content/tus/rhel8/8.4/x86_64/nfv/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/rt/debug',
      'content/tus/rhel8/8.4/x86_64/rt/os',
      'content/tus/rhel8/8.4/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'accountsservice-0.6.50-8.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-0.6.50-8.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-0.6.50-8.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-devel-0.6.50-8.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-devel-0.6.50-8.el8', 'sp':'4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-devel-0.6.50-8.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-devel-0.6.50-8.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-libs-0.6.50-8.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-libs-0.6.50-8.el8', 'sp':'4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-libs-0.6.50-8.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-libs-0.6.50-8.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'appstream-data-8-20191129.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'baobab-3.28.0-4.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clutter-1.26.2-8.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clutter-devel-1.26.2-8.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clutter-doc-1.26.2-8.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-3.28.4-4.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-3.28.4-4.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-3.28.4-4.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-browser-plugin-3.28.4-4.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-browser-plugin-3.28.4-4.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-browser-plugin-3.28.4-4.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-libs-3.28.4-4.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-nautilus-3.28.4-4.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-nautilus-3.28.4-4.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-nautilus-3.28.4-4.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gdm-3.28.3-29.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'gdm-3.28.3-29.el8', 'sp':'4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'gdm-3.28.3-29.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'gdm-3.28.3-29.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'gjs-1.56.2-4.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gjs-devel-1.56.2-4.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-boxes-3.28.5-8.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-control-center-3.28.2-19.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-control-center-3.28.2-19.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-control-center-3.28.2-19.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-control-center-filesystem-3.28.2-19.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-3.13.3-11.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-3.13.3-11.el8', 'sp':'4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-3.13.3-11.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-3.13.3-11.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-devel-3.13.3-11.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-devel-3.13.3-11.el8', 'sp':'4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-devel-3.13.3-11.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-devel-3.13.3-11.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-3.28.2-1.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-3.28.2-1.el8', 'sp':'4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-3.28.2-1.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-3.28.2-1.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-devel-3.28.2-1.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-devel-3.28.2-1.el8', 'sp':'4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-devel-3.28.2-1.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-devel-3.28.2-1.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-remote-desktop-0.1.6-8.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-remote-desktop-0.1.6-8.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-remote-desktop-0.1.6-8.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-3.28.1-8.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-3.28.1-8.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-3.28.1-8.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-wayland-session-3.28.1-8.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-wayland-session-3.28.1-8.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-wayland-session-3.28.1-8.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-xsession-3.28.1-8.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-xsession-3.28.1-8.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-xsession-3.28.1-8.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-settings-daemon-3.32.0-9.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-settings-daemon-3.32.0-9.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-settings-daemon-3.32.0-9.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-shell-3.32.2-14.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-shell-3.32.2-14.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-shell-3.32.2-14.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-software-3.30.6-3.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-software-3.30.6-3.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-software-3.30.6-3.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-software-editor-3.30.6-3.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-software-editor-3.30.6-3.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-software-editor-3.30.6-3.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-terminal-3.28.3-1.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-terminal-3.28.3-1.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-terminal-3.28.3-1.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-terminal-nautilus-3.28.3-1.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-terminal-nautilus-3.28.3-1.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-terminal-nautilus-3.28.3-1.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-tweaks-3.28.1-7.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gsettings-desktop-schemas-3.32.0-4.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gsettings-desktop-schemas-devel-3.32.0-4.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gsettings-desktop-schemas-devel-3.32.0-4.el8', 'sp':'4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gsettings-desktop-schemas-devel-3.32.0-4.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gsettings-desktop-schemas-devel-3.32.0-4.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gtk-update-icon-cache-3.22.30-5.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gtk3-3.22.30-5.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gtk3-devel-3.22.30-5.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gtk3-immodule-xim-3.22.30-5.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-1.36.2-8.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-afc-1.36.2-8.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-afc-1.36.2-8.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-afc-1.36.2-8.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-afp-1.36.2-8.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-afp-1.36.2-8.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-afp-1.36.2-8.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-archive-1.36.2-8.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-archive-1.36.2-8.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-archive-1.36.2-8.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-client-1.36.2-8.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-devel-1.36.2-8.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-fuse-1.36.2-8.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-goa-1.36.2-8.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-goa-1.36.2-8.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-goa-1.36.2-8.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-gphoto2-1.36.2-8.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-mtp-1.36.2-8.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-smb-1.36.2-8.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-1.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-1.el8', 'sp':'4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-1.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-1.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-1.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-1.el8', 'sp':'4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-1.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-1.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvncserver-0.9.11-14.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvncserver-devel-0.9.11-14.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libxslt-1.1.32-4.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libxslt-devel-1.1.32-4.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mozjs52-52.9.0-2.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mozjs52-devel-52.9.0-2.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mozjs60-60.9.0-4.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mozjs60-devel-60.9.0-4.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-3.32.2-34.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-3.32.2-34.el8', 'sp':'4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-3.32.2-34.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-3.32.2-34.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-devel-3.32.2-34.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-devel-3.32.2-34.el8', 'sp':'4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-devel-3.32.2-34.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-devel-3.32.2-34.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-3.28.1-12.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-3.28.1-12.el8', 'sp':'4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-3.28.1-12.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-3.28.1-12.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-devel-3.28.1-12.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-devel-3.28.1-12.el8', 'sp':'4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-devel-3.28.1-12.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-devel-3.28.1-12.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-extensions-3.28.1-12.el8', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-extensions-3.28.1-12.el8', 'sp':'4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-extensions-3.28.1-12.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-extensions-3.28.1-12.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'vala-0.40.19-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'vala-devel-0.40.19-1.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'vinagre-3.22.0-21.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.6/x86_64/appstream/debug',
      'content/aus/rhel8/8.6/x86_64/appstream/os',
      'content/aus/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/aus/rhel8/8.6/x86_64/baseos/debug',
      'content/aus/rhel8/8.6/x86_64/baseos/os',
      'content/aus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/appstream/debug',
      'content/e4s/rhel8/8.6/ppc64le/appstream/os',
      'content/e4s/rhel8/8.6/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/baseos/debug',
      'content/e4s/rhel8/8.6/ppc64le/baseos/os',
      'content/e4s/rhel8/8.6/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/highavailability/debug',
      'content/e4s/rhel8/8.6/ppc64le/highavailability/os',
      'content/e4s/rhel8/8.6/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/sap-solutions/debug',
      'content/e4s/rhel8/8.6/ppc64le/sap-solutions/os',
      'content/e4s/rhel8/8.6/ppc64le/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/sap/debug',
      'content/e4s/rhel8/8.6/ppc64le/sap/os',
      'content/e4s/rhel8/8.6/ppc64le/sap/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/appstream/debug',
      'content/e4s/rhel8/8.6/x86_64/appstream/os',
      'content/e4s/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/baseos/debug',
      'content/e4s/rhel8/8.6/x86_64/baseos/os',
      'content/e4s/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/highavailability/debug',
      'content/e4s/rhel8/8.6/x86_64/highavailability/os',
      'content/e4s/rhel8/8.6/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/sap-solutions/debug',
      'content/e4s/rhel8/8.6/x86_64/sap-solutions/os',
      'content/e4s/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/sap/debug',
      'content/e4s/rhel8/8.6/x86_64/sap/os',
      'content/e4s/rhel8/8.6/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.6/aarch64/appstream/debug',
      'content/eus/rhel8/8.6/aarch64/appstream/os',
      'content/eus/rhel8/8.6/aarch64/appstream/source/SRPMS',
      'content/eus/rhel8/8.6/aarch64/baseos/debug',
      'content/eus/rhel8/8.6/aarch64/baseos/os',
      'content/eus/rhel8/8.6/aarch64/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/aarch64/codeready-builder/debug',
      'content/eus/rhel8/8.6/aarch64/codeready-builder/os',
      'content/eus/rhel8/8.6/aarch64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.6/aarch64/highavailability/debug',
      'content/eus/rhel8/8.6/aarch64/highavailability/os',
      'content/eus/rhel8/8.6/aarch64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.6/aarch64/supplementary/debug',
      'content/eus/rhel8/8.6/aarch64/supplementary/os',
      'content/eus/rhel8/8.6/aarch64/supplementary/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/appstream/debug',
      'content/eus/rhel8/8.6/ppc64le/appstream/os',
      'content/eus/rhel8/8.6/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/baseos/debug',
      'content/eus/rhel8/8.6/ppc64le/baseos/os',
      'content/eus/rhel8/8.6/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/codeready-builder/debug',
      'content/eus/rhel8/8.6/ppc64le/codeready-builder/os',
      'content/eus/rhel8/8.6/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/highavailability/debug',
      'content/eus/rhel8/8.6/ppc64le/highavailability/os',
      'content/eus/rhel8/8.6/ppc64le/highavailability/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/resilientstorage/debug',
      'content/eus/rhel8/8.6/ppc64le/resilientstorage/os',
      'content/eus/rhel8/8.6/ppc64le/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/sap-solutions/debug',
      'content/eus/rhel8/8.6/ppc64le/sap-solutions/os',
      'content/eus/rhel8/8.6/ppc64le/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/sap/debug',
      'content/eus/rhel8/8.6/ppc64le/sap/os',
      'content/eus/rhel8/8.6/ppc64le/sap/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/supplementary/debug',
      'content/eus/rhel8/8.6/ppc64le/supplementary/os',
      'content/eus/rhel8/8.6/ppc64le/supplementary/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/appstream/debug',
      'content/eus/rhel8/8.6/x86_64/appstream/os',
      'content/eus/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/baseos/debug',
      'content/eus/rhel8/8.6/x86_64/baseos/os',
      'content/eus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/highavailability/debug',
      'content/eus/rhel8/8.6/x86_64/highavailability/os',
      'content/eus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/resilientstorage/debug',
      'content/eus/rhel8/8.6/x86_64/resilientstorage/os',
      'content/eus/rhel8/8.6/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/sap-solutions/debug',
      'content/eus/rhel8/8.6/x86_64/sap-solutions/os',
      'content/eus/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/sap/debug',
      'content/eus/rhel8/8.6/x86_64/sap/os',
      'content/eus/rhel8/8.6/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/supplementary/debug',
      'content/eus/rhel8/8.6/x86_64/supplementary/os',
      'content/eus/rhel8/8.6/x86_64/supplementary/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/appstream/debug',
      'content/tus/rhel8/8.6/x86_64/appstream/os',
      'content/tus/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/baseos/debug',
      'content/tus/rhel8/8.6/x86_64/baseos/os',
      'content/tus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/highavailability/debug',
      'content/tus/rhel8/8.6/x86_64/highavailability/os',
      'content/tus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/rt/os',
      'content/tus/rhel8/8.6/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'accountsservice-0.6.50-8.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-0.6.50-8.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-0.6.50-8.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-devel-0.6.50-8.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-devel-0.6.50-8.el8', 'sp':'6', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-devel-0.6.50-8.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-devel-0.6.50-8.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-libs-0.6.50-8.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-libs-0.6.50-8.el8', 'sp':'6', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-libs-0.6.50-8.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-libs-0.6.50-8.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'appstream-data-8-20191129.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'baobab-3.28.0-4.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clutter-1.26.2-8.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clutter-devel-1.26.2-8.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clutter-doc-1.26.2-8.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-3.28.4-4.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-3.28.4-4.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-3.28.4-4.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-browser-plugin-3.28.4-4.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-browser-plugin-3.28.4-4.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-browser-plugin-3.28.4-4.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-libs-3.28.4-4.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-nautilus-3.28.4-4.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-nautilus-3.28.4-4.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-nautilus-3.28.4-4.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gdm-3.28.3-29.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'gdm-3.28.3-29.el8', 'sp':'6', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'gdm-3.28.3-29.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'gdm-3.28.3-29.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'gjs-1.56.2-4.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gjs-devel-1.56.2-4.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-boxes-3.28.5-8.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-control-center-3.28.2-19.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-control-center-3.28.2-19.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-control-center-3.28.2-19.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-control-center-filesystem-3.28.2-19.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-3.13.3-11.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-3.13.3-11.el8', 'sp':'6', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-3.13.3-11.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-3.13.3-11.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-devel-3.13.3-11.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-devel-3.13.3-11.el8', 'sp':'6', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-devel-3.13.3-11.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-devel-3.13.3-11.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-3.28.2-1.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-3.28.2-1.el8', 'sp':'6', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-3.28.2-1.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-3.28.2-1.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-devel-3.28.2-1.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-devel-3.28.2-1.el8', 'sp':'6', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-devel-3.28.2-1.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-devel-3.28.2-1.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-remote-desktop-0.1.6-8.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-remote-desktop-0.1.6-8.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-remote-desktop-0.1.6-8.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-3.28.1-8.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-3.28.1-8.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-3.28.1-8.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-wayland-session-3.28.1-8.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-wayland-session-3.28.1-8.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-wayland-session-3.28.1-8.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-xsession-3.28.1-8.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-xsession-3.28.1-8.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-xsession-3.28.1-8.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-settings-daemon-3.32.0-9.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-settings-daemon-3.32.0-9.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-settings-daemon-3.32.0-9.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-shell-3.32.2-14.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-shell-3.32.2-14.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-shell-3.32.2-14.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-software-3.30.6-3.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-software-3.30.6-3.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-software-3.30.6-3.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-software-editor-3.30.6-3.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-software-editor-3.30.6-3.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-software-editor-3.30.6-3.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-terminal-3.28.3-1.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-terminal-3.28.3-1.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-terminal-3.28.3-1.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-terminal-nautilus-3.28.3-1.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-terminal-nautilus-3.28.3-1.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-terminal-nautilus-3.28.3-1.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-tweaks-3.28.1-7.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gsettings-desktop-schemas-3.32.0-4.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gsettings-desktop-schemas-devel-3.32.0-4.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gsettings-desktop-schemas-devel-3.32.0-4.el8', 'sp':'6', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gsettings-desktop-schemas-devel-3.32.0-4.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gsettings-desktop-schemas-devel-3.32.0-4.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gtk-update-icon-cache-3.22.30-5.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gtk3-3.22.30-5.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gtk3-devel-3.22.30-5.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gtk3-immodule-xim-3.22.30-5.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-1.36.2-8.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-afc-1.36.2-8.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-afc-1.36.2-8.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-afc-1.36.2-8.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-afp-1.36.2-8.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-afp-1.36.2-8.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-afp-1.36.2-8.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-archive-1.36.2-8.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-archive-1.36.2-8.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-archive-1.36.2-8.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-client-1.36.2-8.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-devel-1.36.2-8.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-fuse-1.36.2-8.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-goa-1.36.2-8.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-goa-1.36.2-8.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-goa-1.36.2-8.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-gphoto2-1.36.2-8.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-mtp-1.36.2-8.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-smb-1.36.2-8.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-1.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-1.el8', 'sp':'6', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-1.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-1.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-1.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-1.el8', 'sp':'6', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-1.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-1.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvncserver-0.9.11-14.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvncserver-devel-0.9.11-14.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libxslt-1.1.32-4.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libxslt-devel-1.1.32-4.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mozjs52-52.9.0-2.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mozjs52-devel-52.9.0-2.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mozjs60-60.9.0-4.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mozjs60-devel-60.9.0-4.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-3.32.2-34.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-3.32.2-34.el8', 'sp':'6', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-3.32.2-34.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-3.32.2-34.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-devel-3.32.2-34.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-devel-3.32.2-34.el8', 'sp':'6', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-devel-3.32.2-34.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-devel-3.32.2-34.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-3.28.1-12.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-3.28.1-12.el8', 'sp':'6', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-3.28.1-12.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-3.28.1-12.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-devel-3.28.1-12.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-devel-3.28.1-12.el8', 'sp':'6', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-devel-3.28.1-12.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-devel-3.28.1-12.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-extensions-3.28.1-12.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-extensions-3.28.1-12.el8', 'sp':'6', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-extensions-3.28.1-12.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-extensions-3.28.1-12.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'vala-0.40.19-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'vala-devel-0.40.19-1.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'vinagre-3.22.0-21.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel8/8/aarch64/appstream/debug',
      'content/dist/rhel8/8/aarch64/appstream/os',
      'content/dist/rhel8/8/aarch64/appstream/source/SRPMS',
      'content/dist/rhel8/8/aarch64/baseos/debug',
      'content/dist/rhel8/8/aarch64/baseos/os',
      'content/dist/rhel8/8/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8/aarch64/codeready-builder/os',
      'content/dist/rhel8/8/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/aarch64/highavailability/debug',
      'content/dist/rhel8/8/aarch64/highavailability/os',
      'content/dist/rhel8/8/aarch64/highavailability/source/SRPMS',
      'content/dist/rhel8/8/aarch64/supplementary/debug',
      'content/dist/rhel8/8/aarch64/supplementary/os',
      'content/dist/rhel8/8/aarch64/supplementary/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/appstream/debug',
      'content/dist/rhel8/8/ppc64le/appstream/os',
      'content/dist/rhel8/8/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/baseos/debug',
      'content/dist/rhel8/8/ppc64le/baseos/os',
      'content/dist/rhel8/8/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/codeready-builder/debug',
      'content/dist/rhel8/8/ppc64le/codeready-builder/os',
      'content/dist/rhel8/8/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/highavailability/debug',
      'content/dist/rhel8/8/ppc64le/highavailability/os',
      'content/dist/rhel8/8/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/resilientstorage/debug',
      'content/dist/rhel8/8/ppc64le/resilientstorage/os',
      'content/dist/rhel8/8/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/sap-solutions/debug',
      'content/dist/rhel8/8/ppc64le/sap-solutions/os',
      'content/dist/rhel8/8/ppc64le/sap-solutions/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/sap/debug',
      'content/dist/rhel8/8/ppc64le/sap/os',
      'content/dist/rhel8/8/ppc64le/sap/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/supplementary/debug',
      'content/dist/rhel8/8/ppc64le/supplementary/os',
      'content/dist/rhel8/8/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel8/8/x86_64/appstream/debug',
      'content/dist/rhel8/8/x86_64/appstream/os',
      'content/dist/rhel8/8/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8/x86_64/baseos/debug',
      'content/dist/rhel8/8/x86_64/baseos/os',
      'content/dist/rhel8/8/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8/x86_64/codeready-builder/os',
      'content/dist/rhel8/8/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/x86_64/highavailability/debug',
      'content/dist/rhel8/8/x86_64/highavailability/os',
      'content/dist/rhel8/8/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel8/8/x86_64/nfv/debug',
      'content/dist/rhel8/8/x86_64/nfv/os',
      'content/dist/rhel8/8/x86_64/nfv/source/SRPMS',
      'content/dist/rhel8/8/x86_64/resilientstorage/debug',
      'content/dist/rhel8/8/x86_64/resilientstorage/os',
      'content/dist/rhel8/8/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8/x86_64/rt/debug',
      'content/dist/rhel8/8/x86_64/rt/os',
      'content/dist/rhel8/8/x86_64/rt/source/SRPMS',
      'content/dist/rhel8/8/x86_64/sap-solutions/debug',
      'content/dist/rhel8/8/x86_64/sap-solutions/os',
      'content/dist/rhel8/8/x86_64/sap-solutions/source/SRPMS',
      'content/dist/rhel8/8/x86_64/sap/debug',
      'content/dist/rhel8/8/x86_64/sap/os',
      'content/dist/rhel8/8/x86_64/sap/source/SRPMS',
      'content/dist/rhel8/8/x86_64/supplementary/debug',
      'content/dist/rhel8/8/x86_64/supplementary/os',
      'content/dist/rhel8/8/x86_64/supplementary/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'accountsservice-0.6.50-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-0.6.50-8.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-0.6.50-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-devel-0.6.50-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-devel-0.6.50-8.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-devel-0.6.50-8.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-devel-0.6.50-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-libs-0.6.50-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-libs-0.6.50-8.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-libs-0.6.50-8.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'accountsservice-libs-0.6.50-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'appstream-data-8-20191129.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'baobab-3.28.0-4.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clutter-1.26.2-8.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clutter-devel-1.26.2-8.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'clutter-doc-1.26.2-8.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-3.28.4-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-3.28.4-4.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-3.28.4-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-browser-plugin-3.28.4-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-browser-plugin-3.28.4-4.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-browser-plugin-3.28.4-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-libs-3.28.4-4.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-nautilus-3.28.4-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-nautilus-3.28.4-4.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'evince-nautilus-3.28.4-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gdm-3.28.3-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'gdm-3.28.3-29.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'gdm-3.28.3-29.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'gdm-3.28.3-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'gjs-1.56.2-4.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gjs-devel-1.56.2-4.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-boxes-3.28.5-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-control-center-3.28.2-19.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-control-center-3.28.2-19.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-control-center-3.28.2-19.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-control-center-filesystem-3.28.2-19.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-3.13.3-11.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-3.13.3-11.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-3.13.3-11.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-3.13.3-11.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-devel-3.13.3-11.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-devel-3.13.3-11.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-devel-3.13.3-11.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-menus-devel-3.13.3-11.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-3.28.2-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-3.28.2-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-3.28.2-1.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-3.28.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-devel-3.28.2-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-devel-3.28.2-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-devel-3.28.2-1.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-online-accounts-devel-3.28.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-remote-desktop-0.1.6-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-remote-desktop-0.1.6-8.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-remote-desktop-0.1.6-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-3.28.1-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-3.28.1-8.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-3.28.1-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-wayland-session-3.28.1-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-wayland-session-3.28.1-8.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-wayland-session-3.28.1-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-xsession-3.28.1-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-xsession-3.28.1-8.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-session-xsession-3.28.1-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-settings-daemon-3.32.0-9.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-settings-daemon-3.32.0-9.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-settings-daemon-3.32.0-9.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-shell-3.32.2-14.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-shell-3.32.2-14.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-shell-3.32.2-14.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-software-3.30.6-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-software-3.30.6-3.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-software-3.30.6-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-software-editor-3.30.6-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-software-editor-3.30.6-3.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-software-editor-3.30.6-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-terminal-3.28.3-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-terminal-3.28.3-1.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-terminal-3.28.3-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-terminal-nautilus-3.28.3-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-terminal-nautilus-3.28.3-1.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-terminal-nautilus-3.28.3-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-tweaks-3.28.1-7.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gsettings-desktop-schemas-3.32.0-4.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gsettings-desktop-schemas-devel-3.32.0-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gsettings-desktop-schemas-devel-3.32.0-4.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gsettings-desktop-schemas-devel-3.32.0-4.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gsettings-desktop-schemas-devel-3.32.0-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gtk-update-icon-cache-3.22.30-5.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gtk3-3.22.30-5.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gtk3-devel-3.22.30-5.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gtk3-immodule-xim-3.22.30-5.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-1.36.2-8.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-afc-1.36.2-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-afc-1.36.2-8.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-afc-1.36.2-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-afp-1.36.2-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-afp-1.36.2-8.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-afp-1.36.2-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-archive-1.36.2-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-archive-1.36.2-8.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-archive-1.36.2-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-client-1.36.2-8.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-devel-1.36.2-8.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-fuse-1.36.2-8.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-goa-1.36.2-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-goa-1.36.2-8.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-goa-1.36.2-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-gphoto2-1.36.2-8.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-mtp-1.36.2-8.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gvfs-smb-1.36.2-8.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-1.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-0.19.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-1.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'LibRaw-devel-0.19.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvncserver-0.9.11-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvncserver-devel-0.9.11-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libxslt-1.1.32-4.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libxslt-devel-1.1.32-4.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mozjs52-52.9.0-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mozjs52-devel-52.9.0-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mozjs60-60.9.0-4.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mozjs60-devel-60.9.0-4.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-3.32.2-34.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-3.32.2-34.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-3.32.2-34.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-3.32.2-34.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-devel-3.32.2-34.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-devel-3.32.2-34.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-devel-3.32.2-34.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mutter-devel-3.32.2-34.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-3.28.1-12.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-3.28.1-12.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-3.28.1-12.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-3.28.1-12.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-devel-3.28.1-12.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-devel-3.28.1-12.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-devel-3.28.1-12.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-devel-3.28.1-12.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-extensions-3.28.1-12.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-extensions-3.28.1-12.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-extensions-3.28.1-12.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nautilus-extensions-3.28.1-12.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'vala-0.40.19-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'vala-devel-0.40.19-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'vinagre-3.22.0-21.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  var enterprise_linux_flag = rhel_repo_urls_has_content_dist_rhel(repo_urls:repo_relative_urls);
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
    if (!empty_or_null(pkg['sp']) && !enterprise_linux_flag) sp = pkg['sp'];
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
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'LibRaw / LibRaw-devel / accountsservice / accountsservice-devel / etc');
}
