#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2021-362-01. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156338);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-16275",
    "CVE-2020-12695",
    "CVE-2021-0326",
    "CVE-2021-0535",
    "CVE-2021-27803",
    "CVE-2021-30004"
  );
  script_xref(name:"CEA-ID", value:"CEA-2020-0050");

  script_name(english:"Slackware Linux 14.0 / 14.1 / 14.2 / current wpa_supplicant  Multiple Vulnerabilities (SSA:2021-362-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to wpa_supplicant.");
  script_set_attribute(attribute:"description", value:
"The version of wpa_supplicant installed on the remote host is prior to 2.9. It is, therefore, affected by multiple
vulnerabilities as referenced in the SSA:2021-362-01 advisory.

  - hostapd before 2.10 and wpa_supplicant before 2.10 allow an incorrect indication of disconnection in
    certain situations because source address validation is mishandled. This is a denial of service that
    should have been prevented by PMF (aka management frame protection). The attacker must send a crafted
    802.11 frame from a location that is within the 802.11 communications range. (CVE-2019-16275)

  - The Open Connectivity Foundation UPnP specification before 2020-04-17 does not forbid the acceptance of a
    subscription request with a delivery URL on a different network segment than the fully qualified event-
    subscription URL, aka the CallStranger issue. (CVE-2020-12695)

  - In p2p_copy_client_info of p2p.c, there is a possible out of bounds write due to a missing bounds check.
    This could lead to remote code execution if the target device is performing a Wi-Fi Direct search, with no
    additional execution privileges needed. User interaction is not needed for exploitation.Product:
    AndroidVersions: Android-10 Android-11 Android-8.1 Android-9Android ID: A-172937525 (CVE-2021-0326)

  - In wpas_ctrl_msg_queue_timeout of ctrl_iface_unix.c, there is a possible memory corruption due to a use
    after free. This could lead to local escalation of privilege with System execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android-11Android ID: A-168314741
    (CVE-2021-0535)

  - A vulnerability was discovered in how p2p/p2p_pd.c in wpa_supplicant before 2.10 processes P2P (Wi-Fi
    Direct) provision discovery requests. It could result in denial of service or other impact (potentially
    execution of arbitrary code), for an attacker within radio range. (CVE-2021-27803)

  - In wpa_supplicant and hostapd 2.9, forging attacks may occur because AlgorithmIdentifier parameters are
    mishandled in tls/pkcs1.c and tls/x509v3.c. (CVE-2021-30004)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected wpa_supplicant package.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0326");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:wpa_supplicant");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("slackware.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Slackware", cpu);

var flag = 0;
var constraints = [
    { 'fixed_version' : '2.9', 'product' : 'wpa_supplicant', 'os_name' : 'Slackware Linux', 'os_version' : '14.0', 'service_pack' : '1_slack14.0', 'arch' : 'i486' },
    { 'fixed_version' : '2.9', 'product' : 'wpa_supplicant', 'os_name' : 'Slackware Linux', 'os_version' : '14.0', 'service_pack' : '1_slack14.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '2.9', 'product' : 'wpa_supplicant', 'os_name' : 'Slackware Linux', 'os_version' : '14.1', 'service_pack' : '1_slack14.1', 'arch' : 'i486' },
    { 'fixed_version' : '2.9', 'product' : 'wpa_supplicant', 'os_name' : 'Slackware Linux', 'os_version' : '14.1', 'service_pack' : '1_slack14.1', 'arch' : 'x86_64' },
    { 'fixed_version' : '2.9', 'product' : 'wpa_supplicant', 'os_name' : 'Slackware Linux', 'os_version' : '14.2', 'service_pack' : '1_slack14.2', 'arch' : 'i586' },
    { 'fixed_version' : '2.9', 'product' : 'wpa_supplicant', 'os_name' : 'Slackware Linux', 'os_version' : '14.2', 'service_pack' : '1_slack14.2', 'arch' : 'x86_64' },
    { 'fixed_version' : '2.9', 'product' : 'wpa_supplicant', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '8', 'arch' : 'i586' },
    { 'fixed_version' : '2.9', 'product' : 'wpa_supplicant', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '8', 'arch' : 'x86_64' }
];

foreach constraint (constraints) {
    var pkg_arch = constraint['arch'];
    var arch = NULL;
    if (pkg_arch == "x86_64") {
        arch = pkg_arch;
    }
    if (slackware_check(osver:constraint['os_version'],
                        arch:arch,
                        pkgname:constraint['product'],
                        pkgver:constraint['fixed_version'],
                        pkgarch:pkg_arch,
                        pkgnum:constraint['service_pack'])) flag++;
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : slackware_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
