##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-4647.
##

include('compat.inc');

if (description)
{
  script_id(142775);
  script_version("1.4");
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

  script_name(english:"Oracle Linux 8 : freerdp / and / vinagre (ELSA-2020-4647)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-4647 advisory.

  - In FreeRDP before 2.1.0, there is an out-of-bounds read in cliprdr_read_format_list. Clipboard format data
    read (by client or server) might read data out-of-bounds. This has been fixed in 2.1.0. (CVE-2020-11085)

  - In FreeRDP less than or equal to 2.0.0, there is an out-of-bound read in ntlm_read_AuthenticateMessage.
    This has been fixed in 2.1.0. (CVE-2020-11087)

  - libfreerdp/cache/bitmap.c in FreeRDP versions > 1.0 through 2.0.0-rc4 has an Out of bounds read.
    (CVE-2020-11525)

  - In FreeRDP less than or equal to 2.0.0, when using a manipulated server with USB redirection enabled
    (nearly) arbitrary memory can be read and written due to integer overflows in length checks. This has been
    patched in 2.1.0. (CVE-2020-11039)

  - In FreeRDP greater than 1.2 and before 2.0.0, a double free in update_read_cache_bitmap_v3_order crashes
    the client application if corrupted data from a manipulated server is parsed. This has been patched in
    2.0.0. (CVE-2020-11044)

  - libfreerdp/gdi/gdi.c in FreeRDP > 1.0 through 2.0.0-rc4 has an Out-of-bounds Read. (CVE-2020-11522)

  - In FreeRDP less than or equal to 2.0.0, there is an out-of-bounds read in rfx_process_message_tileset.
    Invalid data fed to RFX decoder results in garbage on screen (as colors). This has been patched in 2.1.0.
    (CVE-2020-11043)

  - In FreeRDP less than or equal to 2.0.0, an Integer Overflow to Buffer Overflow exists. When using /video
    redirection, a manipulated server can instruct the client to allocate a buffer with a smaller size than
    requested due to an integer overflow in size calculation. With later messages, the server can manipulate
    the client to write data out of bound to the previously allocated buffer. This has been patched in 2.1.0.
    (CVE-2020-11038)

  - An issue was discovered in FreeRDP before 2.1.1. An out-of-bounds (OOB) read vulnerability has been
    detected in ntlm_read_ChallengeMessage in winpr/libwinpr/sspi/NTLM/ntlm_message.c. (CVE-2020-13396)

  - In FreeRDP less than or equal to 2.0.0, when running with logger set to WLOG_TRACE, a possible crash of
    application could occur due to a read of an invalid array index. Data could be printed as string to local
    terminal. This has been fixed in 2.1.0. (CVE-2020-11019)

  - In FreeRDP greater than 1.1 and before 2.0.0, there is an out-of-bounds read in update_read_icon_info. It
    allows reading a attacker-defined amount of client memory (32bit unsigned -> 4GB) to an intermediate
    buffer. This can be used to crash the client or store information for later retrieval. This has been
    patched in 2.0.0. (CVE-2020-11042)

  - In FreeRDP less than or equal to 2.0.0, an outside controlled array index is used unchecked for data used
    as configuration for sound backend (alsa, oss, pulse, ...). The most likely outcome is a crash of the
    client instance followed by no or distorted sound or a session disconnect. If a user cannot upgrade to the
    patched version, a workaround is to disable sound for the session. This has been patched in 2.1.0.
    (CVE-2020-11041)

  - An issue was discovered in FreeRDP before 2.1.1. An out-of-bounds (OOB) read vulnerability has been
    detected in security_fips_decrypt in libfreerdp/core/security.c due to an uninitialized value.
    (CVE-2020-13397)

  - In FreeRDP less than or equal to 2.0.0, there is an out-of-bound read in ntlm_read_NegotiateMessage. This
    has been fixed in 2.1.0. (CVE-2020-11088)

  - In FreeRDP less than or equal to 2.0.0, there is an out-of-bound data read from memory in
    clear_decompress_subcode_rlex, visualized on screen as color. This has been patched in 2.1.0.
    (CVE-2020-11040)

  - In FreeRDP after 1.1 and before 2.0.0, a stream out-of-bounds seek in rdp_read_font_capability_set could
    lead to a later out-of-bounds read. As a result, a manipulated client or server might force a disconnect
    due to an invalid data read. This has been fixed in 2.0.0. (CVE-2020-11058)

  - In FreeRDP less than or equal to 2.0.0, a possible resource exhaustion vulnerability can be performed.
    Malicious clients could trigger out of bound reads causing memory allocation with random size. This has
    been fixed in 2.1.0. (CVE-2020-11018)

  - In FreeRDP after 1.0 and before 2.0.0, there is an out-of-bound read in in update_read_bitmap_data that
    allows client memory to be read to an image buffer. The result displayed on screen as colour.
    (CVE-2020-11045)

  - In FreeRDP after 1.0 and before 2.0.0, there is a stream out-of-bounds seek in update_read_synchronize
    that could lead to a later out-of-bounds read. (CVE-2020-11046)

  - In FreeRDP after 1.0 and before 2.0.0, there is an out-of-bounds read. It only allows to abort a session.
    No data extraction is possible. This has been fixed in 2.0.0. (CVE-2020-11048)

  - In FreeRDP after 1.1 and before 2.0.0, there is an out-of-bound read of client memory that is then passed
    on to the protocol parser. This has been patched in 2.0.0. (CVE-2020-11049)

  - In FreeRDP before 2.1.0, there is an out-of-bound read in irp functions (parallel_process_irp_create,
    serial_process_irp_create, drive_process_irp_write, printer_process_irp_write, rdpei_recv_pdu,
    serial_process_irp_write). This has been fixed in 2.1.0. (CVE-2020-11089)

  - libfreerdp/core/update.c in FreeRDP versions > 1.1 through 2.0.0-rc4 has an Out-of-bounds Read.
    (CVE-2020-11526)

  - In FreeRDP less than or equal to 2.0.0, there is an out-of-bound read in
    ntlm_read_ntlm_v2_client_challenge that reads up to 28 bytes out-of-bound to an internal structure. This
    has been fixed in 2.1.0. (CVE-2020-11086)

  - In FreeRDP after 1.1 and before 2.0.0, there is an out-of-bounds read in
    autodetect_recv_bandwidth_measure_results. A malicious server can extract up to 8 bytes of client memory
    with a manipulated message by providing a short input and reading the measurement result data. This has
    been patched in 2.0.0. (CVE-2020-11047)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-4647.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11522");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-13396");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freerdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freerdp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freerdp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libwinpr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libwinpr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:vinagre");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

pkgs = [
    {'reference':'freerdp-2.1.1-1.el8', 'cpu':'aarch64', 'release':'8', 'epoch':'2'},
    {'reference':'freerdp-2.1.1-1.el8', 'cpu':'x86_64', 'release':'8', 'epoch':'2'},
    {'reference':'freerdp-devel-2.1.1-1.el8', 'cpu':'aarch64', 'release':'8', 'epoch':'2'},
    {'reference':'freerdp-devel-2.1.1-1.el8', 'cpu':'i686', 'release':'8', 'epoch':'2'},
    {'reference':'freerdp-devel-2.1.1-1.el8', 'cpu':'x86_64', 'release':'8', 'epoch':'2'},
    {'reference':'freerdp-libs-2.1.1-1.el8', 'cpu':'aarch64', 'release':'8', 'epoch':'2'},
    {'reference':'freerdp-libs-2.1.1-1.el8', 'cpu':'i686', 'release':'8', 'epoch':'2'},
    {'reference':'freerdp-libs-2.1.1-1.el8', 'cpu':'x86_64', 'release':'8', 'epoch':'2'},
    {'reference':'libwinpr-2.1.1-1.el8', 'cpu':'aarch64', 'release':'8', 'epoch':'2'},
    {'reference':'libwinpr-2.1.1-1.el8', 'cpu':'i686', 'release':'8', 'epoch':'2'},
    {'reference':'libwinpr-2.1.1-1.el8', 'cpu':'x86_64', 'release':'8', 'epoch':'2'},
    {'reference':'libwinpr-devel-2.1.1-1.el8', 'cpu':'aarch64', 'release':'8', 'epoch':'2'},
    {'reference':'libwinpr-devel-2.1.1-1.el8', 'cpu':'i686', 'release':'8', 'epoch':'2'},
    {'reference':'libwinpr-devel-2.1.1-1.el8', 'cpu':'x86_64', 'release':'8', 'epoch':'2'},
    {'reference':'vinagre-3.22.0-23.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'vinagre-3.22.0-23.el8', 'cpu':'x86_64', 'release':'8'}
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
  rpm_prefix = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['rpm_prefix'])) rpm_prefix = package_array['rpm_prefix'];
  if (reference && release) {
    if (rpm_prefix) {
        if (rpm_exists(release:release, rpm:rpm_prefix) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'freerdp / freerdp-devel / freerdp-libs / etc');
}