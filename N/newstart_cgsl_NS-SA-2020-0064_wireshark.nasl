##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0064. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143927);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/10");

  script_cve_id(
    "CVE-2018-7418",
    "CVE-2018-11362",
    "CVE-2018-14340",
    "CVE-2018-14341",
    "CVE-2018-14368",
    "CVE-2018-16057",
    "CVE-2018-19622"
  );
  script_bugtraq_id(
    103157,
    104308,
    104847,
    105174,
    106051
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : wireshark Multiple Vulnerabilities (NS-SA-2020-0064)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has wireshark packages installed that are affected
by multiple vulnerabilities:

  - In Wireshark 2.6.0, 2.4.0 to 2.4.6, and 2.2.0 to 2.2.14, the LDSS dissector could crash. This was
    addressed in epan/dissectors/packet-ldss.c by avoiding a buffer over-read upon encountering a missing '\0'
    character. (CVE-2018-11362)

  - In Wireshark 2.2.0 to 2.2.12 and 2.4.0 to 2.4.4, the SIGCOMP dissector could crash. This was addressed in
    epan/dissectors/packet-sigcomp.c by correcting the extraction of the length value. (CVE-2018-7418)

  - In Wireshark 2.6.0 to 2.6.4 and 2.4.0 to 2.4.10, the MMSE dissector could go into an infinite loop. This
    was addressed in epan/dissectors/packet-mmse.c by preventing length overflows. (CVE-2018-19622)

  - In Wireshark 2.6.0 to 2.6.2, 2.4.0 to 2.4.8, and 2.2.0 to 2.2.16, the Radiotap dissector could crash. This
    was addressed in epan/dissectors/packet-ieee80211-radiotap-iter.c by validating iterator operations.
    (CVE-2018-16057)

  - In Wireshark 2.6.0 to 2.6.1, 2.4.0 to 2.4.7, and 2.2.0 to 2.2.15, dissectors that support zlib
    decompression could crash. This was addressed in epan/tvbuff_zlib.c by rejecting negative lengths to avoid
    a buffer over-read. (CVE-2018-14340)

  - In Wireshark 2.6.0 to 2.6.1, 2.4.0 to 2.4.7, and 2.2.0 to 2.2.15, the DICOM dissector could go into a
    large or infinite loop. This was addressed in epan/dissectors/packet-dcm.c by preventing an offset
    overflow. (CVE-2018-14341)

  - In Wireshark 2.6.0 to 2.6.1, 2.4.0 to 2.4.7, and 2.2.0 to 2.2.15, the Bazaar protocol dissector could go
    into an infinite loop. This was addressed in epan/dissectors/packet-bzr.c by properly handling items that
    are too long. (CVE-2018-14368)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0064");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL wireshark packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14368");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL CORE 5.04': [
    'wireshark-1.10.14-24.el7',
    'wireshark-debuginfo-1.10.14-24.el7',
    'wireshark-devel-1.10.14-24.el7',
    'wireshark-gnome-1.10.14-24.el7'
  ],
  'CGSL MAIN 5.04': [
    'wireshark-1.10.14-24.el7',
    'wireshark-debuginfo-1.10.14-24.el7',
    'wireshark-devel-1.10.14-24.el7',
    'wireshark-gnome-1.10.14-24.el7'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'wireshark');
}
