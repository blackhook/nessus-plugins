#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(142333);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/23");

  script_cve_id(
    "CVE-2018-16860",
    "CVE-2019-14861",
    "CVE-2019-14870",
    "CVE-2019-14902",
    "CVE-2019-14907",
    "CVE-2020-14303",
    "CVE-2020-1472"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2020/09/21");
  script_xref(name:"CISA-NCAS", value:"AA22-011A");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");
  script_xref(name:"CEA-ID", value:"CEA-2020-0101");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0008");
  script_xref(name:"CEA-ID", value:"CEA-2020-0121");
  script_xref(name:"CEA-ID", value:"CEA-2023-0016");

  script_name(english:"EulerOS 2.0 SP2 : samba (EulerOS-SA-2020-2396)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the samba packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - An elevation of privilege vulnerability exists when an
    attacker establishes a vulnerable Netlogon secure
    channel connection to a domain controller, using the
    Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon
    Elevation of Privilege Vulnerability'.(CVE-2020-1472)

  - A flaw was found in the AD DC NBT server in all Samba
    versions before 4.10.17, before 4.11.11 and before
    4.12.4. A samba user could send an empty UDP packet to
    cause the samba server to crash.(CVE-2020-14303)

  - There is an issue in all samba 4.11.x versions before
    4.11.5, all samba 4.10.x versions before 4.10.12 and
    all samba 4.9.x versions before 4.9.18, where the
    removal of the right to create or modify a subtree
    would not automatically be taken away on all domain
    controllers.(CVE-2019-14902)

  - All samba versions 4.9.x before 4.9.18, 4.10.x before
    4.10.12 and 4.11.x before 4.11.5 have an issue where if
    it is set with 'log level = 3' (or above) then the
    string obtained from the client, after a failed
    character conversion, is printed. Such strings can be
    provided during the NTLMSSP authentication exchange. In
    the Samba AD DC in particular, this may cause a
    long-lived process(such as the RPC server) to
    terminate. (In the file server case, the most likely
    target, smbd, operates as process-per-client and so a
    crash there is harmless).(CVE-2019-14907)

  - All Samba versions 4.x.x before 4.9.17, 4.10.x before
    4.10.11 and 4.11.x before 4.11.3 have an issue, where
    the (poorly named) dnsserver RPC pipe provides
    administrative facilities to modify DNS records and
    zones. Samba, when acting as an AD DC, stores DNS
    records in LDAP. In AD, the default permissions on the
    DNS partition allow creation of new records by
    authenticated users. This is used for example to allow
    machines to self-register in DNS. If a DNS record was
    created that case-insensitively matched the name of the
    zone, the ldb_qsort() and dns_name_compare() routines
    could be confused into reading memory prior to the list
    of DNS entries when responding to DnssrvEnumRecords()
    or DnssrvEnumRecords2() and so following invalid memory
    as a pointer.(CVE-2019-14861)

  - All Samba versions 4.x.x before 4.9.17, 4.10.x before
    4.10.11 and 4.11.x before 4.11.3 have an issue, where
    the S4U (MS-SFU) Kerberos delegation model includes a
    feature allowing for a subset of clients to be opted
    out of constrained delegation in any way, either
    S4U2Self or regular Kerberos authentication, by forcing
    all tickets for these clients to be non-forwardable. In
    AD this is implemented by a user attribute
    delegation_not_allowed (aka not-delegated), which
    translates to disallow-forwardable. However the Samba
    AD DC does not do that for S4U2Self and does set the
    forwardable flag even if the impersonated client has
    the not-delegated flag set.(CVE-2019-14870)

  - A flaw was found in samba's Heimdal KDC implementation,
    versions 4.8.x up to, excluding 4.8.12, 4.9.x up to,
    excluding 4.9.8 and 4.10.x up to, excluding 4.10.3,
    when used in AD DC mode. A man in the middle attacker
    could use this flaw to intercept the request to the KDC
    and replace the user name (principal) in the request
    with any desired user name (principal) that exists in
    the KDC effectively obtaining a ticket for that
    principal.(CVE-2018-16860)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2396
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b14bf4c");
  script_set_attribute(attribute:"solution", value:
"Update the affected samba packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1472");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["libsmbclient-4.6.2-8.h13",
        "libwbclient-4.6.2-8.h13",
        "samba-4.6.2-8.h13",
        "samba-client-4.6.2-8.h13",
        "samba-client-libs-4.6.2-8.h13",
        "samba-common-4.6.2-8.h13",
        "samba-common-libs-4.6.2-8.h13",
        "samba-common-tools-4.6.2-8.h13",
        "samba-libs-4.6.2-8.h13",
        "samba-python-4.6.2-8.h13",
        "samba-winbind-4.6.2-8.h13",
        "samba-winbind-clients-4.6.2-8.h13",
        "samba-winbind-modules-4.6.2-8.h13"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
