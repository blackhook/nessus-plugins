#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133989);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id(
    "CVE-2018-17199",
    "CVE-2019-10081",
    "CVE-2019-10082",
    "CVE-2019-10097",
    "CVE-2019-9517"
  );
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"EulerOS 2.0 SP8 : httpd (EulerOS-SA-2020-1155)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the httpd packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - In Apache HTTP Server 2.4.32-2.4.39, when mod_remoteip
    was configured to use a trusted intermediary proxy
    server using the 'PROXY' protocol, a specially crafted
    PROXY header could trigger a stack buffer overflow or
    NULL pointer deference. This vulnerability could only
    be triggered by a trusted proxy and not by untrusted
    HTTP clients.(CVE-2019-10097)

  - Some HTTP/2 implementations are vulnerable to
    unconstrained interal data buffering, potentially
    leading to a denial of service. The attacker opens the
    HTTP/2 window so the peer can send without constraint
    however, they leave the TCP window closed so the peer
    cannot actually write (many of) the bytes on the wire.
    The attacker then sends a stream of requests for a
    large response object. Depending on how the servers
    queue the responses, this can consume excess memory,
    CPU, or both.(CVE-2019-9517)

  - HTTP/2 (2.4.20 through 2.4.39) very early pushes, for
    example configured with 'H2PushResource', could lead to
    an overwrite of memory in the pushing request's pool,
    leading to crashes. The memory copied is that of the
    configured push link header values, not data supplied
    by the client.(CVE-2019-10081)

  - In Apache HTTP Server 2.4.18-2.4.39, using fuzzed
    network input, the http/2 session handling could be
    made to read memory after being freed, during
    connection shutdown.(CVE-2019-10082)

  - In Apache HTTP Server 2.4 release 2.4.37 and prior,
    mod_session checks the session expiry time before
    decoding the session. This causes session expiry time
    to be ignored for mod_session_cookie sessions since the
    expiry time is loaded when the session is
    decoded.(CVE-2018-17199)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1155
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2159315e");
  script_set_attribute(attribute:"solution", value:
"Update the affected httpd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10082");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["httpd-2.4.34-8.h11.eulerosv2r8",
        "httpd-devel-2.4.34-8.h11.eulerosv2r8",
        "httpd-filesystem-2.4.34-8.h11.eulerosv2r8",
        "httpd-manual-2.4.34-8.h11.eulerosv2r8",
        "httpd-tools-2.4.34-8.h11.eulerosv2r8",
        "mod_session-2.4.34-8.h11.eulerosv2r8",
        "mod_ssl-2.4.34-8.h11.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd");
}
