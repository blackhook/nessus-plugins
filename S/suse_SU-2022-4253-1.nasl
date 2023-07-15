#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:4253-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(168240);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2011-5325",
    "CVE-2014-9645",
    "CVE-2015-9261",
    "CVE-2016-2147",
    "CVE-2016-2148",
    "CVE-2016-6301",
    "CVE-2017-15873",
    "CVE-2017-15874",
    "CVE-2017-16544",
    "CVE-2018-20679",
    "CVE-2018-1000500",
    "CVE-2018-1000517",
    "CVE-2019-5747",
    "CVE-2021-28831",
    "CVE-2021-42373",
    "CVE-2021-42374",
    "CVE-2021-42375",
    "CVE-2021-42376",
    "CVE-2021-42377",
    "CVE-2021-42378",
    "CVE-2021-42379",
    "CVE-2021-42380",
    "CVE-2021-42381",
    "CVE-2021-42382",
    "CVE-2021-42383",
    "CVE-2021-42384",
    "CVE-2021-42385",
    "CVE-2021-42386"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:4253-1");

  script_name(english:"SUSE SLES12 Security Update : busybox (SUSE-SU-2022:4253-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has a package installed that is affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:4253-1 advisory.

  - Directory traversal vulnerability in the BusyBox implementation of tar before 1.22.0 v5 allows remote
    attackers to point to files outside the current working directory via a symlink. (CVE-2011-5325)

  - The add_probe function in modutils/modprobe.c in BusyBox before 1.23.0 allows local users to bypass
    intended restrictions on loading kernel modules via a / (slash) character in a module name, as
    demonstrated by an ifconfig /usbserial up command or a mount -t /snd_pcm none / command.
    (CVE-2014-9645)

  - huft_build in archival/libarchive/decompress_gunzip.c in BusyBox before 1.27.2 misuses a pointer, causing
    segfaults and an application crash during an unzip operation on a specially crafted ZIP file.
    (CVE-2015-9261)

  - Integer overflow in the DHCP client (udhcpc) in BusyBox before 1.25.0 allows remote attackers to cause a
    denial of service (crash) via a malformed RFC1035-encoded domain name, which triggers an out-of-bounds
    heap write. (CVE-2016-2147)

  - Heap-based buffer overflow in the DHCP client (udhcpc) in BusyBox before 1.25.0 allows remote attackers to
    have unspecified impact via vectors involving OPTION_6RD parsing. (CVE-2016-2148)

  - The recv_and_process_client_pkt function in networking/ntpd.c in busybox allows remote attackers to cause
    a denial of service (CPU and bandwidth consumption) via a forged NTP packet, which triggers a
    communication loop. (CVE-2016-6301)

  - The get_next_block function in archival/libarchive/decompress_bunzip2.c in BusyBox 1.27.2 has an Integer
    Overflow that may lead to a write access violation. (CVE-2017-15873)

  - archival/libarchive/decompress_unlzma.c in BusyBox 1.27.2 has an Integer Underflow that leads to a read
    access violation. (CVE-2017-15874)

  - In the add_match function in libbb/lineedit.c in BusyBox through 1.27.2, the tab autocomplete feature of
    the shell, used to get a list of filenames in a directory, does not sanitize filenames and results in
    executing any escape sequence in the terminal. This could potentially result in code execution, arbitrary
    file writes, or other attacks. (CVE-2017-16544)

  - Busybox contains a Missing SSL certificate validation vulnerability in The busybox wget applet that can
    result in arbitrary code execution. This attack appear to be exploitable via Simply download any file over
    HTTPS using busybox wget https://compromised-domain.com/important-file. (CVE-2018-1000500)

  - BusyBox project BusyBox wget version prior to commit 8e2174e9bd836e53c8b9c6e00d1bc6e2a718686e contains a
    Buffer Overflow vulnerability in Busybox wget that can result in heap buffer overflow. This attack appear
    to be exploitable via network connectivity. This vulnerability appears to have been fixed in after commit
    8e2174e9bd836e53c8b9c6e00d1bc6e2a718686e. (CVE-2018-1000517)

  - An issue was discovered in BusyBox before 1.30.0. An out of bounds read in udhcp components (consumed by
    the DHCP server, client, and relay) allows a remote attacker to leak sensitive information from the stack
    by sending a crafted DHCP message. This is related to verification in udhcp_get_option() in
    networking/udhcp/common.c that 4-byte options are indeed 4 bytes. (CVE-2018-20679)

  - An issue was discovered in BusyBox through 1.30.0. An out of bounds read in udhcp components (consumed by
    the DHCP client, server, and/or relay) might allow a remote attacker to leak sensitive information from
    the stack by sending a crafted DHCP message. This is related to assurance of a 4-byte length when decoding
    DHCP_SUBNET. NOTE: this issue exists because of an incomplete fix for CVE-2018-20679. (CVE-2019-5747)

  - decompress_gunzip.c in BusyBox through 1.32.1 mishandles the error bit on the huft_build result pointer,
    with a resultant invalid free or segmentation fault, via malformed gzip data. (CVE-2021-28831)

  - A NULL pointer dereference in Busybox's man applet leads to denial of service when a section name is
    supplied but no page argument is given (CVE-2021-42373)

  - An out-of-bounds heap read in Busybox's unlzma applet leads to information leak and denial of service when
    crafted LZMA-compressed input is decompressed. This can be triggered by any applet/format that
    (CVE-2021-42374)

  - An incorrect handling of a special element in Busybox's ash applet leads to denial of service when
    processing a crafted shell command, due to the shell mistaking specific characters for reserved
    characters. This may be used for DoS under rare conditions of filtered command input. (CVE-2021-42375)

  - A NULL pointer dereference in Busybox's hush applet leads to denial of service when processing a crafted
    shell command, due to missing validation after a \x03 delimiter character. This may be used for DoS under
    very rare conditions of filtered command input. (CVE-2021-42376)

  - An attacker-controlled pointer free in Busybox's hush applet leads to denial of service and possible code
    execution when processing a crafted shell command, due to the shell mishandling the &&& string. This may
    be used for remote code execution under rare conditions of filtered command input. (CVE-2021-42377)

  - A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when
    processing a crafted awk pattern in the getvar_i function (CVE-2021-42378)

  - A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when
    processing a crafted awk pattern in the next_input_file function (CVE-2021-42379)

  - A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when
    processing a crafted awk pattern in the clrvar function (CVE-2021-42380)

  - A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when
    processing a crafted awk pattern in the hash_init function (CVE-2021-42381)

  - A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when
    processing a crafted awk pattern in the getvar_s function (CVE-2021-42382)

  - A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when
    processing a crafted awk pattern in the evaluate function (CVE-2021-42383, CVE-2021-42385)

  - A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when
    processing a crafted awk pattern in the handle_special function (CVE-2021-42384)

  - A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when
    processing a crafted awk pattern in the nvalloc function (CVE-2021-42386)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/914660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/951562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/970662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/970663");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/991940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1029961");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1064976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1064978");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1069412");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1099260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1099263");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1102912");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1121426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1121428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184522");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192869");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-November/013126.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?968619af");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2011-5325");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-9645");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-9261");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-2147");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-2148");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-6301");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-15873");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-15874");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-16544");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1000500");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1000517");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-5747");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28831");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42373");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42374");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42375");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42376");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42377");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42378");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42379");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42380");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42381");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42382");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42383");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42384");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42385");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42386");
  script_set_attribute(attribute:"solution", value:
"Update the affected busybox package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000517");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-42377");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:busybox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP2/3/4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'busybox-1.35.0-4.3.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'busybox-1.35.0-4.3.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'busybox-1.35.0-4.3.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'busybox-1.35.0-4.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.3']},
    {'reference':'busybox-1.35.0-4.3.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'busybox');
}
