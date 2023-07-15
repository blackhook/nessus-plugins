##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4724-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146302);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-36221",
    "CVE-2020-36222",
    "CVE-2020-36223",
    "CVE-2020-36224",
    "CVE-2020-36225",
    "CVE-2020-36226",
    "CVE-2020-36227",
    "CVE-2020-36228",
    "CVE-2020-36229",
    "CVE-2020-36230"
  );
  script_xref(name:"USN", value:"4724-1");
  script_xref(name:"IAVB", value:"2021-B-0014");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 : OpenLDAP vulnerabilities (USN-4724-1)");
  script_summary(english:"Checks the dpkg output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4724-1 advisory.

  - An integer underflow was discovered in OpenLDAP before 2.4.57 leading to slapd crashes in the Certificate
    Exact Assertion processing, resulting in denial of service (schema_init.c serialNumberAndIssuerCheck).
    (CVE-2020-36221)

  - A flaw was discovered in OpenLDAP before 2.4.57 leading to an assertion failure in slapd in the
    saslAuthzTo validation, resulting in denial of service. (CVE-2020-36222)

  - A flaw was discovered in OpenLDAP before 2.4.57 leading to a slapd crash in the Values Return Filter
    control handling, resulting in denial of service (double free and out-of-bounds read). (CVE-2020-36223)

  - A flaw was discovered in OpenLDAP before 2.4.57 leading to an invalid pointer free and slapd crash in the
    saslAuthzTo processing, resulting in denial of service. (CVE-2020-36224)

  - A flaw was discovered in OpenLDAP before 2.4.57 leading to a double free and slapd crash in the
    saslAuthzTo processing, resulting in denial of service. (CVE-2020-36225)

  - A flaw was discovered in OpenLDAP before 2.4.57 leading to a memch->bv_len miscalculation and slapd crash
    in the saslAuthzTo processing, resulting in denial of service. (CVE-2020-36226)

  - A flaw was discovered in OpenLDAP before 2.4.57 leading to an infinite loop in slapd with the cancel_extop
    Cancel operation, resulting in denial of service. (CVE-2020-36227)

  - An integer underflow was discovered in OpenLDAP before 2.4.57 leading to a slapd crash in the Certificate
    List Exact Assertion processing, resulting in denial of service. (CVE-2020-36228)

  - A flaw was discovered in ldap_X509dn2bv in OpenLDAP before 2.4.57 leading to a slapd crash in the X.509 DN
    parsing in ad_keystring, resulting in denial of service. (CVE-2020-36229)

  - A flaw was discovered in OpenLDAP before 2.4.57 leading in an assertion failure in slapd in the X.509 DN
    parsing in decode.c ber_next_element, resulting in denial of service. (CVE-2020-36230)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4724-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36230");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ldap-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libldap-2.4-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libldap-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libldap2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slapd-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slapd-smbk5pwd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slapi-dev");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(16\.04|18\.04|20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'ldap-utils', 'pkgver': '2.4.42+dfsg-2ubuntu3.12'},
    {'osver': '16.04', 'pkgname': 'libldap-2.4-2', 'pkgver': '2.4.42+dfsg-2ubuntu3.12'},
    {'osver': '16.04', 'pkgname': 'libldap2-dev', 'pkgver': '2.4.42+dfsg-2ubuntu3.12'},
    {'osver': '16.04', 'pkgname': 'slapd', 'pkgver': '2.4.42+dfsg-2ubuntu3.12'},
    {'osver': '16.04', 'pkgname': 'slapd-smbk5pwd', 'pkgver': '2.4.42+dfsg-2ubuntu3.12'},
    {'osver': '18.04', 'pkgname': 'ldap-utils', 'pkgver': '2.4.45+dfsg-1ubuntu1.9'},
    {'osver': '18.04', 'pkgname': 'libldap-2.4-2', 'pkgver': '2.4.45+dfsg-1ubuntu1.9'},
    {'osver': '18.04', 'pkgname': 'libldap-common', 'pkgver': '2.4.45+dfsg-1ubuntu1.9'},
    {'osver': '18.04', 'pkgname': 'libldap2-dev', 'pkgver': '2.4.45+dfsg-1ubuntu1.9'},
    {'osver': '18.04', 'pkgname': 'slapd', 'pkgver': '2.4.45+dfsg-1ubuntu1.9'},
    {'osver': '18.04', 'pkgname': 'slapd-smbk5pwd', 'pkgver': '2.4.45+dfsg-1ubuntu1.9'},
    {'osver': '20.04', 'pkgname': 'ldap-utils', 'pkgver': '2.4.49+dfsg-2ubuntu1.6'},
    {'osver': '20.04', 'pkgname': 'libldap-2.4-2', 'pkgver': '2.4.49+dfsg-2ubuntu1.6'},
    {'osver': '20.04', 'pkgname': 'libldap-common', 'pkgver': '2.4.49+dfsg-2ubuntu1.6'},
    {'osver': '20.04', 'pkgname': 'libldap2-dev', 'pkgver': '2.4.49+dfsg-2ubuntu1.6'},
    {'osver': '20.04', 'pkgname': 'slapd', 'pkgver': '2.4.49+dfsg-2ubuntu1.6'},
    {'osver': '20.04', 'pkgname': 'slapd-contrib', 'pkgver': '2.4.49+dfsg-2ubuntu1.6'},
    {'osver': '20.04', 'pkgname': 'slapd-smbk5pwd', 'pkgver': '2.4.49+dfsg-2ubuntu1.6'},
    {'osver': '20.04', 'pkgname': 'slapi-dev', 'pkgver': '2.4.49+dfsg-2ubuntu1.6'},
    {'osver': '20.10', 'pkgname': 'ldap-utils', 'pkgver': '2.4.53+dfsg-1ubuntu1.3'},
    {'osver': '20.10', 'pkgname': 'libldap-2.4-2', 'pkgver': '2.4.53+dfsg-1ubuntu1.3'},
    {'osver': '20.10', 'pkgname': 'libldap-common', 'pkgver': '2.4.53+dfsg-1ubuntu1.3'},
    {'osver': '20.10', 'pkgname': 'libldap2-dev', 'pkgver': '2.4.53+dfsg-1ubuntu1.3'},
    {'osver': '20.10', 'pkgname': 'slapd', 'pkgver': '2.4.53+dfsg-1ubuntu1.3'},
    {'osver': '20.10', 'pkgname': 'slapd-contrib', 'pkgver': '2.4.53+dfsg-1ubuntu1.3'},
    {'osver': '20.10', 'pkgname': 'slapd-smbk5pwd', 'pkgver': '2.4.53+dfsg-1ubuntu1.3'},
    {'osver': '20.10', 'pkgname': 'slapi-dev', 'pkgver': '2.4.53+dfsg-1ubuntu1.3'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ldap-utils / libldap-2.4-2 / libldap-common / libldap2-dev / slapd / etc');
}