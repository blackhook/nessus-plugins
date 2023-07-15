#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2021:3151.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157743);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/14");

  script_cve_id("CVE-2021-3621");
  script_xref(name:"RLSA", value:"2021:3151");

  script_name(english:"Rocky Linux 8 : sssd (RLSA-2021:3151)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2021:3151 advisory.

  - A flaw was found in SSSD, where the sssctl command was vulnerable to shell command injection via the logs-
    fetch and cache-expire subcommands. This flaw allows an attacker to trick the root user into running a
    specially crafted sssctl command, such as via sudo, to gain root access. The highest threat from this
    vulnerability is to confidentiality, integrity, as well as system availability. (CVE-2021-3621)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2021:3151");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1975142");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3621");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libipa_hbac-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libsss_autofs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libsss_autofs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libsss_certmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libsss_certmap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libsss_certmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libsss_idmap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libsss_nss_idmap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libsss_nss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libsss_simpleifp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libsss_simpleifp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libsss_simpleifp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libsss_sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libsss_sudo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-libipa_hbac-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-libsss_nss_idmap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-sss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-sss-murmur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-sss-murmur-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-sssdconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-ad-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-common-pac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-common-pac-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-dbus-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-ipa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-kcm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-kcm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-krb5-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-libwbclient-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-nfs-idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-nfs-idmap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-polkit-rules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-proxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-winbind-idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sssd-winbind-idmap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/RockyLinux/release');
if (isnull(release) || 'Rocky Linux' >!< release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'libipa_hbac-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac-2.4.0-9.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac-debuginfo-2.4.0-9.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac-devel-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac-devel-2.4.0-9.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac-devel-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_autofs-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_autofs-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_autofs-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_autofs-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_certmap-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_certmap-2.4.0-9.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_certmap-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_certmap-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_certmap-debuginfo-2.4.0-9.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_certmap-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_certmap-devel-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_certmap-devel-2.4.0-9.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_certmap-devel-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-2.4.0-9.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-debuginfo-2.4.0-9.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-devel-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-devel-2.4.0-9.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-devel-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-2.4.0-9.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-debuginfo-2.4.0-9.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-devel-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-devel-2.4.0-9.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-devel-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp-2.4.0-9.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp-debuginfo-2.4.0-9.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp-devel-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp-devel-2.4.0-9.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp-devel-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_sudo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_sudo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_sudo-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_sudo-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libipa_hbac-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libipa_hbac-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libipa_hbac-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libipa_hbac-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libsss_nss_idmap-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libsss_nss_idmap-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libsss_nss_idmap-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libsss_nss_idmap-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-sss-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-sss-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-sss-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-sss-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-sss-murmur-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-sss-murmur-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-sss-murmur-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-sss-murmur-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-sssdconfig-2.4.0-9.el8_4.2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ad-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ad-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ad-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ad-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-client-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-client-2.4.0-9.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-client-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-client-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-client-debuginfo-2.4.0-9.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-client-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-common-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-common-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-common-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-common-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-common-pac-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-common-pac-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-common-pac-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-common-pac-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-dbus-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-dbus-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-dbus-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-dbus-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-debuginfo-2.4.0-9.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-debugsource-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-debugsource-2.4.0-9.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-debugsource-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ipa-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ipa-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ipa-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ipa-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-kcm-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-kcm-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-kcm-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-kcm-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-krb5-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-krb5-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-krb5-common-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-krb5-common-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-krb5-common-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-krb5-common-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-krb5-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-krb5-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ldap-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ldap-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ldap-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ldap-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-libwbclient-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-libwbclient-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-libwbclient-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-libwbclient-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-libwbclient-devel-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-libwbclient-devel-2.4.0-9.el8_4.2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-libwbclient-devel-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-nfs-idmap-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-nfs-idmap-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-nfs-idmap-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-nfs-idmap-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-polkit-rules-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-polkit-rules-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-proxy-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-proxy-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-proxy-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-proxy-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-tools-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-tools-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-tools-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-tools-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-winbind-idmap-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-winbind-idmap-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-winbind-idmap-debuginfo-2.4.0-9.el8_4.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-winbind-idmap-debuginfo-2.4.0-9.el8_4.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libipa_hbac / libipa_hbac-debuginfo / libipa_hbac-devel / etc');
}
