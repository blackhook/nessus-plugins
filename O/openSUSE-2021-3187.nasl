#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:3187-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153579);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2020-27840", "CVE-2021-20254", "CVE-2021-20277");
  script_xref(name:"IAVA", value:"2021-A-0140-S");
  script_xref(name:"IAVA", value:"2021-A-0208-S");

  script_name(english:"openSUSE 15 Security Update : samba (openSUSE-SU-2021:3187-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:3187-1 advisory.

  - A flaw was found in samba. Spaces used in a string around a domain name (DN), while supposed to be
    ignored, can cause invalid DN strings with spaces to instead write a zero-byte into out-of-bounds memory,
    resulting in a crash. The highest threat from this vulnerability is to system availability.
    (CVE-2020-27840)

  - A flaw was found in samba. The Samba smbd file server must map Windows group identities (SIDs) into unix
    group ids (gids). The code that performs this had a flaw that could allow it to read data beyond the end
    of the array in the case where a negative cache entry had been added to the mapping cache. This could
    cause the calling code to return those values into the process token that stores the group membership for
    a user. The highest threat from this vulnerability is to data confidentiality and integrity.
    (CVE-2021-20254)

  - A flaw was found in Samba's libldb. Multiple, consecutive leading spaces in an LDAP attribute can lead to
    an out-of-bounds memory write, leading to a crash of the LDAP server process handling the request. The
    highest threat from this vulnerability is to system availability. (CVE-2021-20277)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189875");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ANLZ3MSWRYNRTSO7FPC7CORZ4WAS3YKE/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ddbf654c");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27840");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20254");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20277");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20254");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-pcp-pmda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-binding0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-binding0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-errors-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-errors0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-errors0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy-python3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0-python3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-ad-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-ad-dc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-dsdb-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-python3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'ctdb-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ctdb-pcp-pmda-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ctdb-tests-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc-binding0-32bit-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc-binding0-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc-devel-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc-samr-devel-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc-samr0-32bit-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc-samr0-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc0-32bit-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc0-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-devel-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-krb5pac-devel-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-krb5pac0-32bit-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-krb5pac0-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-nbt-devel-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-nbt0-32bit-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-nbt0-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-standard-devel-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-standard0-32bit-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-standard0-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr1-32bit-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr1-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnetapi-devel-32bit-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnetapi-devel-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnetapi0-32bit-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnetapi0-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-credentials-devel-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-credentials0-32bit-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-credentials0-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-errors-devel-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-errors0-32bit-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-errors0-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-hostconfig-devel-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-hostconfig0-32bit-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-hostconfig0-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-passdb-devel-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-passdb0-32bit-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-passdb0-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-policy-devel-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-policy-python3-devel-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-policy0-python3-32bit-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-policy0-python3-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-util-devel-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-util0-32bit-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-util0-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamdb-devel-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamdb0-32bit-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamdb0-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient-devel-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient0-32bit-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient0-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbconf-devel-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbconf0-32bit-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbconf0-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbldap-devel-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbldap2-32bit-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbldap2-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtevent-util-devel-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtevent-util0-32bit-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtevent-util0-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient-devel-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient0-32bit-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient0-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-ad-dc-32bit-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-ad-dc-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-ceph-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-ceph-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-32bit-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-core-devel-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dsdb-modules-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-32bit-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-python3-32bit-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-python3-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-python3-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-32bit-4.13.6+git.211.555d60b24ba-3.7.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-4.13.6+git.211.555d60b24ba-3.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ctdb / ctdb-pcp-pmda / ctdb-tests / libdcerpc-binding0 / etc');
}
