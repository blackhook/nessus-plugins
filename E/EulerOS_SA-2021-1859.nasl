#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149199);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/04");

  script_cve_id(
    "CVE-2018-11362",
    "CVE-2018-14340",
    "CVE-2018-14341",
    "CVE-2018-14368",
    "CVE-2018-16057",
    "CVE-2018-19622",
    "CVE-2018-5336",
    "CVE-2018-7418",
    "CVE-2019-10894",
    "CVE-2019-10895",
    "CVE-2019-10899",
    "CVE-2019-10901",
    "CVE-2019-10903"
  );

  script_name(english:"EulerOS 2.0 SP3 : wireshark (EulerOS-SA-2021-1859)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the wireshark packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - In Wireshark 2.2.0 to 2.2.12 and 2.4.0 to 2.4.4, the
    SIGCOMP dissector could crash. This was addressed in
    epan/dissectors/packet-sigcomp.c by correcting the
    extraction of the length value.(CVE-2018-7418)

  - In Wireshark 2.4.0 to 2.4.13, 2.6.0 to 2.6.7, and
    3.0.0, the DCERPC SPOOLSS dissector could crash. This
    was addressed in
    epan/dissectors/packet-dcerpc-spoolss.c by adding a
    boundary check.(CVE-2019-10903)

  - In Wireshark 2.4.0 to 2.4.13, 2.6.0 to 2.6.7, and
    3.0.0, the GSS-API dissector could crash. This was
    addressed in epan/dissectors/packet-gssapi.c by
    ensuring that a valid dissector is
    called.(CVE-2019-10894)

  - In Wireshark 2.4.0 to 2.4.13, 2.6.0 to 2.6.7, and
    3.0.0, the LDSS dissector could crash. This was
    addressed in epan/dissectors/packet-ldss.c by handling
    file digests properly.(CVE-2019-10901)

  - In Wireshark 2.4.0 to 2.4.13, 2.6.0 to 2.6.7, and
    3.0.0, the NetScaler file parser could crash. This was
    addressed in wiretap/netscaler.c by improving data
    validation.(CVE-2019-10895)

  - In Wireshark 2.4.0 to 2.4.13, 2.6.0 to 2.6.7, and
    3.0.0, the SRVLOC dissector could crash. This was
    addressed in epan/dissectors/packet-srvloc.c by
    preventing a heap-based buffer
    under-read.(CVE-2019-10899)

  - In Wireshark 2.4.0 to 2.4.3 and 2.2.0 to 2.2.11, the
    JSON, XML, NTP, XMPP, and GDB dissectors could crash.
    This was addressed in epan/tvbparse.c by limiting the
    recursion depth.(CVE-2018-5336)

  - In Wireshark 2.6.0 to 2.6.1, 2.4.0 to 2.4.7, and 2.2.0
    to 2.2.15, dissectors that support zlib decompression
    could crash. This was addressed in epan/tvbuff_zlib.c
    by rejecting negative lengths to avoid a buffer
    over-read.(CVE-2018-14340)

  - In Wireshark 2.6.0 to 2.6.1, 2.4.0 to 2.4.7, and 2.2.0
    to 2.2.15, the Bazaar protocol dissector could go into
    an infinite loop. This was addressed in
    epan/dissectors/packet-bzr.c by properly handling items
    that are too long.(CVE-2018-14368)

  - In Wireshark 2.6.0 to 2.6.1, 2.4.0 to 2.4.7, and 2.2.0
    to 2.2.15, the DICOM dissector could go into a large or
    infinite loop. This was addressed in
    epan/dissectors/packet-dcm.c by preventing an offset
    overflow.(CVE-2018-14341)

  - In Wireshark 2.6.0 to 2.6.2, 2.4.0 to 2.4.8, and 2.2.0
    to 2.2.16, the Radiotap dissector could crash. This was
    addressed in
    epan/dissectors/packet-ieee80211-radiotap-iter.c by
    validating iterator operations.(CVE-2018-16057)

  - In Wireshark 2.6.0 to 2.6.4 and 2.4.0 to 2.4.10, the
    MMSE dissector could go into an infinite loop. This was
    addressed in epan/dissectors/packet-mmse.c by
    preventing length overflows.(CVE-2018-19622)

  - In Wireshark 2.6.0, 2.4.0 to 2.4.6, and 2.2.0 to
    2.2.14, the LDSS dissector could crash. This was
    addressed in epan/dissectors/packet-ldss.c by avoiding
    a buffer over-read upon encountering a missing '\0'
    character.(CVE-2018-11362)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1859
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2025aba1");
  script_set_attribute(attribute:"solution", value:
"Update the affected wireshark packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["wireshark-1.10.14-7.h4",
        "wireshark-gnome-1.10.14-7.h4"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");
}
