#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153350);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/16");

  script_cve_id(
    "CVE-2019-10894",
    "CVE-2019-10895",
    "CVE-2019-10899",
    "CVE-2019-10901",
    "CVE-2019-10903"
  );

  script_name(english:"EulerOS 2.0 SP2 : wireshark (EulerOS-SA-2021-2438)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the wireshark packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - Wireshark is a network traffic analyzer for Unix-ish
    operating systems.This package lays base for libpcap, a
    packet capture and filtering library, contains
    command-line utilities, contains plugins and
    documentation for wireshark. A graphical user interface
    is packaged separately to GTK+ package.Security
    Fix(es):In Wireshark 2.4.0 to 2.4.13, 2.6.0 to 2.6.7,
    and 3.0.0, the LDSS dissector could crash. This was
    addressed in epan/dissectors/packet-ldss.c by handling
    file digests properly.(CVE-2019-10901)In Wireshark
    2.4.0 to 2.4.13, 2.6.0 to 2.6.7, and 3.0.0, the GSS-API
    dissector could crash. This was addressed in
    epan/dissectors/packet-gssapi.c by ensuring that a
    valid dissector is called.(CVE-2019-10894)In Wireshark
    2.4.0 to 2.4.13, 2.6.0 to 2.6.7, and 3.0.0, the
    NetScaler file parser could crash. This was addressed
    in wiretap etscaler.c by improving data
    validation.(CVE-2019-10895)In Wireshark 2.4.0 to
    2.4.13, 2.6.0 to 2.6.7, and 3.0.0, the SRVLOC dissector
    could crash. This was addressed in
    epan/dissectors/packet-srvloc.c by preventing a
    heap-based buffer under-read.(CVE-2019-10899)In
    Wireshark 2.4.0 to 2.4.13, 2.6.0 to 2.6.7, and 3.0.0,
    the DCERPC SPOOLSS dissector could crash. This was
    addressed in epan/dissectors/packet-dcerpc-spoolss.c by
    adding a boundary check.(CVE-2019-10903)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2438
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64da330b");
  script_set_attribute(attribute:"solution", value:
"Update the affected wireshark packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10903");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/14");

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
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["wireshark-1.10.14-7.h13",
        "wireshark-gnome-1.10.14-7.h13"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");
}
