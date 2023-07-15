#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2022-08d2138578
#

include('compat.inc');

if (description)
{
  script_id(169266);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/23");

  script_cve_id(
    "CVE-2022-23468",
    "CVE-2022-23477",
    "CVE-2022-23478",
    "CVE-2022-23479",
    "CVE-2022-23480",
    "CVE-2022-23481",
    "CVE-2022-23482",
    "CVE-2022-23483",
    "CVE-2022-23484",
    "CVE-2022-23493"
  );
  script_xref(name:"FEDORA", value:"2022-08d2138578");

  script_name(english:"Fedora 36 : 1:xrdp (2022-08d2138578)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 36 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2022-08d2138578 advisory.

  - xrdp is an open source project which provides a graphical login to remote machines using Microsoft Remote
    Desktop Protocol (RDP). xrdp < v0.9.21 contain a buffer over flow in xrdp_login_wnd_create() function.
    There are no known workarounds for this issue. Users are advised to upgrade. (CVE-2022-23468)

  - xrdp is an open source project which provides a graphical login to remote machines using Microsoft Remote
    Desktop Protocol (RDP). xrdp < v0.9.21 contain a buffer over flow in audin_send_open() function. There are
    no known workarounds for this issue. Users are advised to upgrade. (CVE-2022-23477)

  - xrdp is an open source project which provides a graphical login to remote machines using Microsoft Remote
    Desktop Protocol (RDP). xrdp < v0.9.21 contain a Out of Bound Write in
    xrdp_mm_trans_process_drdynvc_channel_open() function. There are no known workarounds for this issue.
    Users are advised to upgrade. (CVE-2022-23478)

  - xrdp is an open source project which provides a graphical login to remote machines using Microsoft Remote
    Desktop Protocol (RDP). xrdp < v0.9.21 contain a buffer over flow in xrdp_mm_chan_data_in() function.
    There are no known workarounds for this issue. Users are advised to upgrade. (CVE-2022-23479)

  - xrdp is an open source project which provides a graphical login to remote machines using Microsoft Remote
    Desktop Protocol (RDP). xrdp < v0.9.21 contain a buffer over flow in
    devredir_proc_client_devlist_announce_req() function. There are no known workarounds for this issue. Users
    are advised to upgrade. (CVE-2022-23480)

  - xrdp is an open source project which provides a graphical login to remote machines using Microsoft Remote
    Desktop Protocol (RDP). xrdp < v0.9.21 contain a Out of Bound Read in xrdp_caps_process_confirm_active()
    function. There are no known workarounds for this issue. Users are advised to upgrade. (CVE-2022-23481)

  - xrdp is an open source project which provides a graphical login to remote machines using Microsoft Remote
    Desktop Protocol (RDP). xrdp < v0.9.21 contain a Out of Bound Read in xrdp_sec_process_mcs_data_CS_CORE()
    function. There are no known workarounds for this issue. Users are advised to upgrade. (CVE-2022-23482)

  - xrdp is an open source project which provides a graphical login to remote machines using Microsoft Remote
    Desktop Protocol (RDP). xrdp < v0.9.21 contain a Out of Bound Read in libxrdp_send_to_channel() function.
    There are no known workarounds for this issue. Users are advised to upgrade. (CVE-2022-23483)

  - xrdp is an open source project which provides a graphical login to remote machines using Microsoft Remote
    Desktop Protocol (RDP). xrdp < v0.9.21 contain a Integer Overflow in
    xrdp_mm_process_rail_update_window_text() function. There are no known workarounds for this issue. Users
    are advised to upgrade. (CVE-2022-23484)

  - xrdp is an open source project which provides a graphical login to remote machines using Microsoft Remote
    Desktop Protocol (RDP). xrdp < v0.9.21 contain a Out of Bound Read in
    xrdp_mm_trans_process_drdynvc_channel_close() function. There are no known workarounds for this issue.
    Users are advised to upgrade. (CVE-2022-23493)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2022-08d2138578");
  script_set_attribute(attribute:"solution", value:
"Update the affected 1:xrdp package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23484");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xrdp");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^36([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 36', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'xrdp-0.9.21-1.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, '1:xrdp');
}
