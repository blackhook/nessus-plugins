#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130684);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2016-2365",
    "CVE-2016-2366",
    "CVE-2016-2367",
    "CVE-2016-2369",
    "CVE-2016-2370",
    "CVE-2016-2371",
    "CVE-2016-2372",
    "CVE-2016-2373",
    "CVE-2016-2374",
    "CVE-2016-2375",
    "CVE-2016-2376",
    "CVE-2016-2377",
    "CVE-2016-2378",
    "CVE-2016-2380",
    "CVE-2016-4323"
  );

  script_name(english:"EulerOS 2.0 SP5 : pidgin (EulerOS-SA-2019-2222)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the pidgin package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - Pidgin is an instant messaging program which can log in
    to multiple accounts on multiple instant messaging
    networks simultaneously.Security Fix(es):A buffer
    overflow vulnerability exists in the handling of the
    MXIT protocol Pidgin. Specially crafted data sent via
    the server could potentially result in a buffer
    overflow, potentially resulting in memory corruption. A
    malicious server or an unfiltered malicious user can
    send negative length values to trigger this
    vulnerability.(CVE-2016-2378)A buffer overflow
    vulnerability exists in the handling of the MXIT
    protocol in Pidgin. Specially crafted MXIT data sent
    from the server could potentially result in arbitrary
    code execution. A malicious server or an attacker who
    intercepts the network traffic can send an invalid size
    for a packet which will trigger a buffer
    overflow.(CVE-2016-2376)An exploitable out-of-bounds
    read exists in the handling of the MXIT protocol in
    Pidgin. Specially crafted MXIT contact information sent
    from the server can result in memory
    disclosure.(CVE-2016-2375)An exploitable memory
    corruption vulnerability exists in the handling of the
    MXIT protocol in Pidgin. Specially crafted MXIT MultiMX
    message sent via the server can result in an
    out-of-bounds write leading to memory disclosure and
    code execution.(CVE-2016-2374)A buffer overflow
    vulnerability exists in the handling of the MXIT
    protocol in Pidgin. Specially crafted MXIT data sent by
    the server could potentially result in an out-of-bounds
    write of one byte. A malicious server can send a
    negative content-length in response to a HTTP request
    triggering the vulnerability.(CVE-2016-2377)A denial of
    service vulnerability exists in the handling of the
    MXIT protocol in Pidgin. Specially crafted MXIT data
    sent via the server could potentially result in an
    out-of-bounds read. A malicious server or user can send
    an invalid mood to trigger this
    vulnerability.(CVE-2016-2373)An out-of-bounds write
    vulnerability exists in the handling of the MXIT
    protocol in Pidgin. Specially crafted MXIT data sent
    via the server could cause memory corruption resulting
    in code execution.(CVE-2016-2371)A directory traversal
    exists in the handling of the MXIT protocol in Pidgin.
    Specially crafted MXIT data sent from the server could
    potentially result in an overwrite of files. A
    malicious server or someone with access to the network
    traffic can provide an invalid filename for a splash
    image triggering the vulnerability.(CVE-2016-4323)An
    information leak exists in the handling of the MXIT
    protocol in Pidgin. Specially crafted MXIT data sent to
    the server could potentially result in an out-of-bounds
    read. A user could be convinced to enter a particular
    string which would then get converted incorrectly and
    could lead to a potential out-of-bounds
    read.(CVE-2016-2380)An information leak exists in the
    handling of the MXIT protocol in Pidgin. Specially
    crafted MXIT data sent via the server could potentially
    result in an out-of-bounds read. A malicious user,
    server, or man-in-the-middle attacker can send an
    invalid size for a file transfer which will trigger an
    out-of-bounds read vulnerability. This could result in
    a denial of service or copy data from memory to the
    file, resulting in an information leak if the file is
    sent to another user.(CVE-2016-2372)A NULL pointer
    dereference vulnerability exists in the handling of the
    MXIT protocol in Pidgin. Specially crafted MXIT data
    sent via the server could potentially result in a
    denial of service vulnerability. A malicious server can
    send a packet starting with a NULL byte triggering the
    vulnerability.(CVE-2016-2369)A denial of service
    vulnerability exists in the handling of the MXIT
    protocol in Pidgin. Specially crafted MXIT data sent
    from the server could potentially result in an
    out-of-bounds read. A malicious server or
    man-in-the-middle attacker can send invalid data to
    trigger this vulnerability.(CVE-2016-2370)A denial of
    service vulnerability exists in the handling of the
    MXIT protocol in Pidgin. Specially crafted MXIT data
    sent via the server could potentially result in a null
    pointer dereference. A malicious server or an attacker
    who intercepts the network traffic can send invalid
    data to trigger this vulnerability and cause a
    crash.(CVE-2016-2365)A denial of service vulnerability
    exists in the handling of the MXIT protocol in Pidgin.
    Specially crafted MXIT data sent via the server could
    potentially result in an out-of-bounds read. A
    malicious server or an attacker who intercepts the
    network traffic can send invalid data to trigger this
    vulnerability and cause a crash.(CVE-2016-2366)An
    information leak exists in the handling of the MXIT
    protocol in Pidgin. Specially crafted MXIT data sent
    via the server could potentially result in an
    out-of-bounds read. A malicious user, server, or
    man-in-the-middle can send an invalid size for an
    avatar which will trigger an out-of-bounds read
    vulnerability. This could result in a denial of service
    or copy data from memory to the file, resulting in an
    information leak if the avatar is sent to another
    user.(CVE-2016-2367)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2222
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?02e21c73");
  script_set_attribute(attribute:"solution", value:
"Update the affected pidgin packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libpurple");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["libpurple-2.10.11-7.h4.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pidgin");
}
