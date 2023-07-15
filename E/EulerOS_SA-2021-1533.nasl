#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(147047);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/23");

  script_cve_id(
    "CVE-2020-10730",
    "CVE-2020-10760",
    "CVE-2020-14318",
    "CVE-2020-14323",
    "CVE-2020-14383",
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

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.6.0 : samba (EulerOS-SA-2021-1533)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the samba packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - An elevation of privilege vulnerability exists when an
    attacker establishes a vulnerable Netlogon secure
    channel connection to a domain controller, using the
    Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon
    Elevation of Privilege Vulnerability'.(CVE-2020-1472)

  - A null pointer dereference flaw was found in samba's
    Winbind service in versions before 4.11.15, before
    4.12.9 and before 4.13.1. A local user could use this
    flaw to crash the winbind service causing denial of
    service.(CVE-2020-14323)

  - A flaw was found in the way samba handled file and
    directory permissions. An authenticated user could use
    this flaw to gain access to certain file and directory
    information which otherwise would be unavailable to the
    attacker.(CVE-2020-14318)

  - A use-after-free flaw was found in all samba LDAP
    server versions before 4.10.17, before 4.11.11, before
    4.12.4 used in a AC DC configuration. A Samba LDAP user
    could use this flaw to crash samba.(CVE-2020-10760)

  - A NULL pointer dereference, or possible use-after-free
    flaw was found in Samba AD LDAP server in versions
    before 4.10.17, before 4.11.11 and before 4.12.4.
    Although some versions of Samba shipped with Red Hat
    Enterprise Linux do not support Samba in AD mode, the
    affected code is shipped with the libldb package. This
    flaw allows an authenticated user to possibly trigger a
    use-after-free or NULL pointer dereference. The highest
    threat from this vulnerability is to system
    availability.(CVE-2020-10730)

  - A flaw was found in samba's DNS server. An
    authenticated user could use this flaw to the RPC
    server to crash. This RPC server, which also serves
    protocols other than dnsserver, will be restarted after
    a short delay, but it is easy for an authenticated non
    administrative attacker to crash it again as soon as it
    returns. The Samba DNS server itself will continue to
    operate, but many RPC services will
    not.(CVE-2020-14383)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1533
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72dbb1c2");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["libsmbclient-4.9.1-2.h29.eulerosv2r8",
        "libwbclient-4.9.1-2.h29.eulerosv2r8",
        "samba-client-libs-4.9.1-2.h29.eulerosv2r8",
        "samba-common-4.9.1-2.h29.eulerosv2r8",
        "samba-common-libs-4.9.1-2.h29.eulerosv2r8",
        "samba-common-tools-4.9.1-2.h29.eulerosv2r8",
        "samba-libs-4.9.1-2.h29.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
