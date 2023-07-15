#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-7ac413b969
#

include('compat.inc');

if (description)
{
  script_id(173783);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/11");

  script_cve_id("CVE-2023-0225", "CVE-2023-0614", "CVE-2023-0922");
  script_xref(name:"IAVA", value:"2023-A-0167");
  script_xref(name:"FEDORA", value:"2023-7ac413b969");

  script_name(english:"Fedora 38 : libldb / samba (2023-7ac413b969)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 38 host has packages installed that are affected by multiple vulnerabilities as referenced in the
FEDORA-2023-7ac413b969 advisory.

  - In implementing the Validated dnsHostName permission check in Samba's Active Directory DC, and therefore
    applying correctly constraints on the values of a dnsHostName value for a computer in a Samba domain
    (CVE-2022-32743), the case where the dnsHostName is deleted, rather than modified or added, was
    incorrectly handled. Therefore, in Samba 4.17.0 and later an LDAP attribute value deletion of the
    dnsHostName attribute became possible for authenticated but otherwise unprivileged users, for any object.
    (CVE-2023-0225)

  - Active Directory allows passwords to be set and changed over LDAP. Microsoft's implementation imposes a
    restriction that this may only happen over an encrypted connection, however Samba does not have this
    restriction currently. Samba's samba-tool client tool likewise has no restriction regarding the security
    of the connection it will set a password over. An attacker able to observe the network traffic between
    samba-tool and the Samba AD DC could obtain newly set passwords if samba-tool connected using a Kerberos
    secured LDAP connection against a Samba AD DC. This would happen when samba-tool was used to reset a
    user's password, or to add a new user. This only impacts connections made using Kerberos as NTLM-protected
    connections are upgraded to encryption regardless. This patch changes all Samba AD LDAP client connections
    to use encryption, as well as integrity protection, by default, by changing the default value of client
    ldap sasl wrapping to seal in Samba's smb.conf. Administrators should confirm this value has not been
    overridden in their local smb.conf to obtain the benefit of this change. NOTE WELL: Samba, for
    consistency, uses a common smb.conf option for LDAP client behaviour. Therefore this will also encrypt the
    AD LDAP connections between Samba's winbindd and any AD DC, so this patch will also change behaviour for
    Samba Domain Member configurations. If this is a concern, the smb.conf value client ldap sasl wrapping
    can be reset to sign. (CVE-2023-0922)

  - In Active Directory, there are essentially four different classes of attributes. - Secret attributes (such
    as a user, computer or domain trust password) that are never disclosed and are not available to search
    against over LDAP. This is a hard-coded list, and since Samba 4.8 these are additionally encrypted in the
    DB with a per-DB key. - Confidential attributes (marked as such in the schema) that have a default access
    restriction allowing access only to the owner of the object. While a Samba AD Domain makes these
    attributes available, thankfully by default it will not have any of these confidential attributes set, as
    they are only added by clients after configuration (typically via a GPO). Examples of confidential data
    stored in Active Directory include BitLocker recovery keys, TPM owner passwords, and certificate secret
    keys stored with Credential Roaming. - Access controlled attributes (for reads or writes), Samba will
    honour the access control specified in the ntSecurityDescriptor. - Public attributes for read. Most
    attributes in Active Directory are available to read by all authenticated users. Because the access
    control rules for a given attribute are not consistent between objects, Samba implemented access control
    restrictions only after matching objects against the filter. Taking each of the above classes in turn: -
    Secret attributes are prevented from disclosure firstly by redaction of the LDAP filter, and secondly by
    the fact that they are still encrypted during filter processing (by default). - Confidential and access
    controlled attributes were subject to an attack using LDAP filters. With this security patch, for
    attributes mentioned in the search filter, Samba will perform a per-object access control evaluation
    before LDAP filter matching on the attribute, preventing unauthorised disclosure of the value of (for
    example) BitLocker recovery keys. It is not expected that all similar attacks have been prevented, and it
    is likely still possible to determine if an object or attribute on an object is present, but not to obtain
    the contents. (CVE-2023-0614)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-7ac413b969");
  script_set_attribute(attribute:"solution", value:
"Update the affected 2:samba and / or libldb packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0614");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:samba");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^38([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 38', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'libldb-2.7.2-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-4.18.1-0.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libldb / samba');
}
