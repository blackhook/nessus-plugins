#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132629);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2019-11555",
    "CVE-2019-9497",
    "CVE-2019-9498",
    "CVE-2019-9499"
  );

  script_name(english:"EulerOS 2.0 SP8 : wpa_supplicant (EulerOS-SA-2020-1036)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the wpa_supplicant package installed,
the EulerOS installation on the remote host is affected by the
following vulnerabilities :

  - The implementations of EAP-PWD in hostapd EAP Server
    and wpa_supplicant EAP Peer do not validate the scalar
    and element values in EAP-pwd-Commit. This
    vulnerability may allow an attacker to complete EAP-PWD
    authentication without knowing the password. However,
    unless the crypto library does not implement additional
    checks for the EC point, the attacker will not be able
    to derive the session key or complete the key exchange.
    Both hostapd with SAE support and wpa_supplicant with
    SAE support prior to and including version 2.4 are
    affected. Both hostapd with EAP-pwd support and
    wpa_supplicant with EAP-pwd support prior to and
    including version 2.7 are affected.(CVE-2019-9497)

  - The implementations of EAP-PWD in hostapd EAP Server,
    when built against a crypto library missing explicit
    validation on imported elements, do not validate the
    scalar and element values in EAP-pwd-Commit. An
    attacker may be able to use invalid scalar/element
    values to complete authentication, gaining session key
    and network access without needing or learning the
    password. Both hostapd with SAE support and
    wpa_supplicant with SAE support prior to and including
    version 2.4 are affected. Both hostapd with EAP-pwd
    support and wpa_supplicant with EAP-pwd support prior
    to and including version 2.7 are
    affected.(CVE-2019-9498)

  - The implementations of EAP-PWD in wpa_supplicant EAP
    Peer, when built against a crypto library missing
    explicit validation on imported elements, do not
    validate the scalar and element values in
    EAP-pwd-Commit. An attacker may complete
    authentication, session key and control of the data
    connection with a client. Both hostapd with SAE support
    and wpa_supplicant with SAE support prior to and
    including version 2.4 are affected. Both hostapd with
    EAP-pwd support and wpa_supplicant with EAP-pwd support
    prior to and including version 2.7 are
    affected.(CVE-2019-9499)

  - The EAP-pwd implementation in hostapd (EAP server)
    before 2.8 and wpa_supplicant (EAP peer) before 2.8
    does not validate fragmentation reassembly state
    properly for a case where an unexpected fragment could
    be received. This could result in process termination
    due to a NULL pointer dereference (denial of service).
    This affects eap_server/eap_server_pwd.c and
    eap_peer/eap_pwd.c.(CVE-2019-11555)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1036
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?508f85e6");
  script_set_attribute(attribute:"solution", value:
"Update the affected wpa_supplicant packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:wpa_supplicant");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["wpa_supplicant-2.6-17.h4.eulerosv2r8"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wpa_supplicant");
}
