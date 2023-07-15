#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151902);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id("CVE-2020-8616", "CVE-2020-8617", "CVE-2020-8623");

  script_name(english:"EulerOS Virtualization 3.0.2.2 : bind (EulerOS-SA-2021-2127)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the bind packages installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - Bind-utils contains a collection of utilities for
    querying DNS (Domain Name System) name servers to find
    out information about Internet hosts. These tools will
    provide you with the IP addresses for given host names,
    as well as other information about registered domains
    andnetwork addresses.You should install bind-utils if
    you need to get information from DNS name
    servers.Security Fix(es):In BIND 9.10.0 -> 9.11.21,
    9.12.0 -> 9.16.5, 9.17.0 -> 9.17.3, also affects
    9.10.5-S1 -> 9.11.21-S1 of the BIND 9 Supported Preview
    Edition, An attacker that can reach a vulnerable system
    with a specially crafted query packet can trigger a
    crash. To be vulnerable, the system must: * be running
    BIND that was built with '--enable-native-pkcs11' * be
    signing one or more zones with an RSA key * be able to
    receive queries from a possible
    attacker(CVE-2020-8623)A malicious actor who
    intentionally exploits this lack of effective
    limitation on the number of fetches performed when
    processing referrals can, through the use of specially
    crafted referrals, cause a recursing server to issue a
    very large number of fetches in an attempt to process
    the referral. This has at least two potential effects:
    The performance of the recursing server can potentially
    be degraded by the additional work required to perform
    these fetches, and The attacker can exploit this
    behavior to use the recursing server as a reflector in
    a reflection attack with a high amplification
    factor.(CVE-2020-8616)Using a specially-crafted
    message, an attacker may potentially cause a BIND
    server to reach an inconsistent state if the attacker
    knows (or successfully guesses) the name of a TSIG key
    used by the server. Since BIND, by default, configures
    a local session key even on servers whose configuration
    does not otherwise make use of it, almost all current
    BIND servers are vulnerable. In releases of BIND dating
    from March 2018 and after, an assertion check in tsig.c
    detects this inconsistent state and deliberately exits.
    Prior to the introduction of the check the server would
    continue operating in an inconsistent state, with
    potentially harmful results.(CVE-2020-8617)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2127
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?431ac256");
  script_set_attribute(attribute:"solution", value:
"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8617");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-8616");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.2") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.2");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["bind-libs-9.9.4-61.1.h15.eulerosv2r7",
        "bind-libs-lite-9.9.4-61.1.h15.eulerosv2r7",
        "bind-license-9.9.4-61.1.h15.eulerosv2r7",
        "bind-utils-9.9.4-61.1.h15.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind");
}
