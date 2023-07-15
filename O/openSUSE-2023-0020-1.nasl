#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2023:0020-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(170098);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2019-14870",
    "CVE-2021-3671",
    "CVE-2021-44758",
    "CVE-2022-3437",
    "CVE-2022-41916",
    "CVE-2022-42898",
    "CVE-2022-44640"
  );

  script_name(english:"openSUSE 15 Security Update : libheimdal (openSUSE-SU-2023:0020-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2023:0020-1 advisory.

  - All Samba versions 4.x.x before 4.9.17, 4.10.x before 4.10.11 and 4.11.x before 4.11.3 have an issue,
    where the S4U (MS-SFU) Kerberos delegation model includes a feature allowing for a subset of clients to be
    opted out of constrained delegation in any way, either S4U2Self or regular Kerberos authentication, by
    forcing all tickets for these clients to be non-forwardable. In AD this is implemented by a user attribute
    delegation_not_allowed (aka not-delegated), which translates to disallow-forwardable. However the Samba AD
    DC does not do that for S4U2Self and does set the forwardable flag even if the impersonated client has the
    not-delegated flag set. (CVE-2019-14870)

  - A null pointer de-reference was found in the way samba kerberos server handled missing sname in TGS-REQ
    (Ticket Granting Server - Request). An authenticated user could use this flaw to crash the samba server.
    (CVE-2021-3671)

  - Heimdal before 7.7.1 allows attackers to cause a NULL pointer dereference in a SPNEGO acceptor via a
    preferred_mech_type of GSS_C_NO_OID and a nonzero initial_response value to send_accept. (CVE-2021-44758)

  - A heap-based buffer overflow vulnerability was found in Samba within the GSSAPI unwrap_des() and
    unwrap_des3() routines of Heimdal. The DES and Triple-DES decryption routines in the Heimdal GSSAPI
    library allow a length-limited write buffer overflow on malloc() allocated memory when presented with a
    maliciously small packet. This flaw allows a remote user to send specially crafted malicious data to the
    application, possibly resulting in a denial of service (DoS) attack. (CVE-2022-3437)

  - Heimdal is an implementation of ASN.1/DER, PKIX, and Kerberos. Versions prior to 7.7.1 are vulnerable to a
    denial of service vulnerability in Heimdal's PKI certificate validation library, affecting the KDC (via
    PKINIT) and kinit (via PKINIT), as well as any third-party applications using Heimdal's libhx509. Users
    should upgrade to Heimdal 7.7.1 or 7.8. There are no known workarounds for this issue. (CVE-2022-41916)

  - PAC parsing in MIT Kerberos 5 (aka krb5) before 1.19.4 and 1.20.x before 1.20.1 has integer overflows that
    may lead to remote code execution (in KDC, kadmind, or a GSS or Kerberos application server) on 32-bit
    platforms (which have a resultant heap-based buffer overflow), and cause a denial of service on other
    platforms. This occurs in krb5_pac_parse in lib/krb5/krb/pac.c. Heimdal before 7.7.1 has a similar bug.
    (CVE-2022-42898)

  - Heimdal before 7.7.1 allows remote attackers to execute arbitrary code because of an invalid free in the
    ASN.1 codec used by the Key Distribution Center (KDC). (CVE-2022-44640)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VCW7YX6RG5EAFBRU3SLTXKN5NWVODXTH/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99f274fe");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-14870");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3671");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-44758");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3437");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-41916");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42898");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-44640");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14870");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-44640");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasn1-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgssapi3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhcrypto4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhdb9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libheimbase1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libheimdal-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libheimedit0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libheimntlm0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhx509-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkadm5clnt7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkadm5srv8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkafs0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkrb5-26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libotp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libroken18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsl0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwind0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'libasn1-8-7.8.0-bp153.2.4.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgssapi3-7.8.0-bp153.2.4.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libhcrypto4-7.8.0-bp153.2.4.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libhdb9-7.8.0-bp153.2.4.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libheimbase1-7.8.0-bp153.2.4.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libheimdal-devel-7.8.0-bp153.2.4.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libheimedit0-7.8.0-bp153.2.4.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libheimntlm0-7.8.0-bp153.2.4.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libhx509-5-7.8.0-bp153.2.4.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libkadm5clnt7-7.8.0-bp153.2.4.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libkadm5srv8-7.8.0-bp153.2.4.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libkafs0-7.8.0-bp153.2.4.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libkdc2-7.8.0-bp153.2.4.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libkrb5-26-7.8.0-bp153.2.4.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libotp0-7.8.0-bp153.2.4.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libroken18-7.8.0-bp153.2.4.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsl0-7.8.0-bp153.2.4.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwind0-7.8.0-bp153.2.4.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libasn1-8 / libgssapi3 / libhcrypto4 / libhdb9 / libheimbase1 / etc');
}
