##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:4031 and
# CentOS Errata and Security Advisory 2020:4031 respectively.
##

include('compat.inc');

if (description)
{
  script_id(141578);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2020-11018",
    "CVE-2020-11019",
    "CVE-2020-11038",
    "CVE-2020-11039",
    "CVE-2020-11040",
    "CVE-2020-11041",
    "CVE-2020-11042",
    "CVE-2020-11043",
    "CVE-2020-11044",
    "CVE-2020-11045",
    "CVE-2020-11046",
    "CVE-2020-11047",
    "CVE-2020-11048",
    "CVE-2020-11049",
    "CVE-2020-11058",
    "CVE-2020-11085",
    "CVE-2020-11086",
    "CVE-2020-11087",
    "CVE-2020-11088",
    "CVE-2020-11089",
    "CVE-2020-11522",
    "CVE-2020-11525",
    "CVE-2020-11526",
    "CVE-2020-13396",
    "CVE-2020-13397"
  );
  script_xref(name:"RHSA", value:"2020:4031");

  script_name(english:"CentOS 7 : freerdp (CESA-2020:4031)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2020:4031 advisory.

  - freerdp: Out of bound read in cliprdr_server_receive_capabilities (CVE-2020-11018)

  - freerdp: Out of bound read in update_recv could result in a crash (CVE-2020-11019)

  - freerdp: Integer overflow in VIDEO channel (CVE-2020-11038)

  - freerdp: Out of bound read/write in usb redirection channel (CVE-2020-11039)

  - freerdp: Out of bound access in clear_decompress_subcode_rlex (CVE-2020-11040)

  - freerdp: Unchecked read of array offset in rdpsnd_recv_wave2_pdu (CVE-2020-11041)

  - freerdp: out-of-bounds read in update_read_icon_info function (CVE-2020-11042)

  - freerdp: out of bound read in rfx_process_message_tileset (CVE-2020-11043)

  - freerdp: double free in update_read_cache_bitmap_v3_order function (CVE-2020-11044)

  - freerdp: out of bounds read in update_read_bitmap_data function (CVE-2020-11045)

  - freerdp: out of bounds seek in update_read_synchronize function could lead out of bounds read
    (CVE-2020-11046)

  - freerdp: out-of-bounds read in autodetect_recv_bandwidth_measure_results function (CVE-2020-11047)

  - freerdp: out-of-bounds read could result in aborting the session (CVE-2020-11048)

  - freerdp: out-of-bound read of client memory that is then passed on to the protocol parser (CVE-2020-11049)

  - freerdp: stream out-of-bounds seek in rdp_read_font_capability_set could lead to out-of-bounds read
    (CVE-2020-11058)

  - freerdp: out-of-bounds read in cliprdr_read_format_list function (CVE-2020-11085)

  - freerdp: out-of-bounds read in ntlm_read_ntlm_v2_client_challenge function (CVE-2020-11086)

  - freerdp: out-of-bounds read in ntlm_read_AuthenticateMessage (CVE-2020-11087)

  - freerdp: out-of-bounds read in ntlm_read_NegotiateMessage (CVE-2020-11088)

  - freerdp: out-of-bounds read in irp functions (CVE-2020-11089)

  - freerdp: out-of-bounds read in gdi.c (CVE-2020-11522)

  - freerdp: out-of-bounds read in bitmap.c (CVE-2020-11525)

  - freerdp: Stream pointer out of bounds in update_recv_secondary_order could lead out of bounds read later
    (CVE-2020-11526)

  - freerdp: Out-of-bounds read in ntlm_read_ChallengeMessage in winpr/libwinpr/sspi/NTLM/ntlm_message.c.
    (CVE-2020-13396)

  - freerdp: Out-of-bounds read in security_fips_decrypt in libfreerdp/core/security.c (CVE-2020-13397)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-October/012703.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4c3a180");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/20.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/119.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/125.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/129.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/190.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/476.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/672.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/770.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/787.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/805.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11522");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-13396");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20, 119, 125, 129, 190, 476, 672, 770, 787, 805);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freerdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freerdp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freerdp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwinpr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwinpr-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'CentOS 7.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

pkgs = [
    {'reference':'freerdp-2.1.1-2.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'freerdp-devel-2.1.1-2.el7', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'freerdp-devel-2.1.1-2.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'freerdp-libs-2.1.1-2.el7', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'freerdp-libs-2.1.1-2.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'libwinpr-2.1.1-2.el7', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'libwinpr-2.1.1-2.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'libwinpr-devel-2.1.1-2.el7', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'libwinpr-devel-2.1.1-2.el7', 'cpu':'x86_64', 'release':'CentOS-7'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +
    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'freerdp / freerdp-devel / freerdp-libs / etc');
}