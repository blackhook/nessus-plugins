#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:3087. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(175895);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id(
    "CVE-2022-21594",
    "CVE-2022-21599",
    "CVE-2022-21604",
    "CVE-2022-21608",
    "CVE-2022-21611",
    "CVE-2022-21617",
    "CVE-2022-21625",
    "CVE-2022-21632",
    "CVE-2022-21633",
    "CVE-2022-21637",
    "CVE-2022-21640",
    "CVE-2022-39400",
    "CVE-2022-39408",
    "CVE-2022-39410",
    "CVE-2023-21836",
    "CVE-2023-21863",
    "CVE-2023-21864",
    "CVE-2023-21865",
    "CVE-2023-21867",
    "CVE-2023-21868",
    "CVE-2023-21869",
    "CVE-2023-21870",
    "CVE-2023-21871",
    "CVE-2023-21873",
    "CVE-2023-21874",
    "CVE-2023-21875",
    "CVE-2023-21876",
    "CVE-2023-21877",
    "CVE-2023-21878",
    "CVE-2023-21879",
    "CVE-2023-21880",
    "CVE-2023-21881",
    "CVE-2023-21882",
    "CVE-2023-21883",
    "CVE-2023-21887",
    "CVE-2023-21912",
    "CVE-2023-21917"
  );
  script_xref(name:"IAVA", value:"2022-A-0432");
  script_xref(name:"IAVA", value:"2023-A-0043");
  script_xref(name:"IAVA", value:"2023-A-0212");
  script_xref(name:"RHSA", value:"2023:3087");

  script_name(english:"RHEL 8 : mysql:8.0 (RHSA-2023:3087)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:3087 advisory.

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.30 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. (CVE-2022-21594, CVE-2022-21640, CVE-2022-39400, CVE-2023-21864, CVE-2023-21865,
    CVE-2023-21917)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Stored Procedure). Supported
    versions that are affected are 8.0.30 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. (CVE-2022-21599)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 8.0.30 and prior. Easily exploitable vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL
    Server. (CVE-2022-21604, CVE-2022-21637)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 5.7.39 and prior and 8.0.30 and prior. Easily exploitable vulnerability
    allows high privileged attacker with network access via multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server. (CVE-2022-21608)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 8.0.30 and prior. Difficult to exploit vulnerability allows high privileged attacker with
    logon to the infrastructure where MySQL Server executes to compromise MySQL Server. Successful attacks of
    this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash
    (complete DOS) of MySQL Server. (CVE-2022-21611)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Connection Handling).
    Supported versions that are affected are 5.7.39 and prior and 8.0.30 and prior. Easily exploitable
    vulnerability allows high privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2022-21617)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.30 and prior. Difficult to exploit vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. (CVE-2022-21625)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Security: Privileges).
    Supported versions that are affected are 8.0.30 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. (CVE-2022-21632)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Replication). Supported
    versions that are affected are 8.0.30 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. (CVE-2022-21633)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.30 and prior. Easily exploitable vulnerability allows low privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. (CVE-2022-39408, CVE-2022-39410)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DML). Supported versions
    that are affected are 8.0.31 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. (CVE-2023-21836)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.31 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. (CVE-2023-21863, CVE-2023-21867, CVE-2023-21870, CVE-2023-21873, CVE-2023-21876,
    CVE-2023-21878, CVE-2023-21879, CVE-2023-21881, CVE-2023-21883)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.31 and prior. Easily exploitable vulnerability allows low privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. (CVE-2023-21868)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 8.0.31 and prior. Easily exploitable vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL
    Server as well as unauthorized update, insert or delete access to some of MySQL Server accessible data.
    (CVE-2023-21869, CVE-2023-21877, CVE-2023-21880)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 8.0.31 and prior. Easily exploitable vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL
    Server. (CVE-2023-21871)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Thread Pooling). Supported
    versions that are affected are 8.0.30 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of
    MySQL Server. (CVE-2023-21874)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Security: Encryption).
    Supported versions that are affected are 8.0.31 and prior. Difficult to exploit vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized creation, deletion or modification access to
    critical data or all MySQL Server accessible data and unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server. (CVE-2023-21875)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.31 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized update, insert or delete access to some of MySQL Server
    accessible data. (CVE-2023-21882)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: GIS). Supported versions
    that are affected are 8.0.31 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. (CVE-2023-21887)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Security: Privileges).
    Supported versions that are affected are 5.7.41 and prior and 8.0.30 and prior. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2023-21912)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21594");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21599");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21604");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21608");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21611");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21617");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21625");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21632");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21633");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21637");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21640");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-39400");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-39408");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-39410");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21836");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21863");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21864");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21865");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21867");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21868");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21869");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21870");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21871");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21873");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21874");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21875");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21876");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21877");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21878");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21879");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21880");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21881");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21882");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21883");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21887");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21912");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21917");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:3087");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21880");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-21875");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mecab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mecab-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mecab-ipadic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mecab-ipadic-EUCJP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-test");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var appstreams = {
  'mysql:8.0': [
    {
      'repo_relative_urls': [
        'content/dist/rhel8/8/aarch64/appstream/debug',
        'content/dist/rhel8/8/aarch64/appstream/os',
        'content/dist/rhel8/8/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8/aarch64/baseos/debug',
        'content/dist/rhel8/8/aarch64/baseos/os',
        'content/dist/rhel8/8/aarch64/baseos/source/SRPMS',
        'content/dist/rhel8/8/aarch64/codeready-builder/debug',
        'content/dist/rhel8/8/aarch64/codeready-builder/os',
        'content/dist/rhel8/8/aarch64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/aarch64/highavailability/debug',
        'content/dist/rhel8/8/aarch64/highavailability/os',
        'content/dist/rhel8/8/aarch64/highavailability/source/SRPMS',
        'content/dist/rhel8/8/aarch64/supplementary/debug',
        'content/dist/rhel8/8/aarch64/supplementary/os',
        'content/dist/rhel8/8/aarch64/supplementary/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/appstream/debug',
        'content/dist/rhel8/8/ppc64le/appstream/os',
        'content/dist/rhel8/8/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/baseos/debug',
        'content/dist/rhel8/8/ppc64le/baseos/os',
        'content/dist/rhel8/8/ppc64le/baseos/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/codeready-builder/debug',
        'content/dist/rhel8/8/ppc64le/codeready-builder/os',
        'content/dist/rhel8/8/ppc64le/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/highavailability/debug',
        'content/dist/rhel8/8/ppc64le/highavailability/os',
        'content/dist/rhel8/8/ppc64le/highavailability/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/resilientstorage/debug',
        'content/dist/rhel8/8/ppc64le/resilientstorage/os',
        'content/dist/rhel8/8/ppc64le/resilientstorage/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/sap-solutions/debug',
        'content/dist/rhel8/8/ppc64le/sap-solutions/os',
        'content/dist/rhel8/8/ppc64le/sap-solutions/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/sap/debug',
        'content/dist/rhel8/8/ppc64le/sap/os',
        'content/dist/rhel8/8/ppc64le/sap/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/supplementary/debug',
        'content/dist/rhel8/8/ppc64le/supplementary/os',
        'content/dist/rhel8/8/ppc64le/supplementary/source/SRPMS',
        'content/dist/rhel8/8/s390x/appstream/debug',
        'content/dist/rhel8/8/s390x/appstream/os',
        'content/dist/rhel8/8/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8/s390x/baseos/debug',
        'content/dist/rhel8/8/s390x/baseos/os',
        'content/dist/rhel8/8/s390x/baseos/source/SRPMS',
        'content/dist/rhel8/8/s390x/codeready-builder/debug',
        'content/dist/rhel8/8/s390x/codeready-builder/os',
        'content/dist/rhel8/8/s390x/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/s390x/highavailability/debug',
        'content/dist/rhel8/8/s390x/highavailability/os',
        'content/dist/rhel8/8/s390x/highavailability/source/SRPMS',
        'content/dist/rhel8/8/s390x/resilientstorage/debug',
        'content/dist/rhel8/8/s390x/resilientstorage/os',
        'content/dist/rhel8/8/s390x/resilientstorage/source/SRPMS',
        'content/dist/rhel8/8/s390x/sap/debug',
        'content/dist/rhel8/8/s390x/sap/os',
        'content/dist/rhel8/8/s390x/sap/source/SRPMS',
        'content/dist/rhel8/8/s390x/supplementary/debug',
        'content/dist/rhel8/8/s390x/supplementary/os',
        'content/dist/rhel8/8/s390x/supplementary/source/SRPMS',
        'content/dist/rhel8/8/x86_64/appstream/debug',
        'content/dist/rhel8/8/x86_64/appstream/os',
        'content/dist/rhel8/8/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8/x86_64/baseos/debug',
        'content/dist/rhel8/8/x86_64/baseos/os',
        'content/dist/rhel8/8/x86_64/baseos/source/SRPMS',
        'content/dist/rhel8/8/x86_64/codeready-builder/debug',
        'content/dist/rhel8/8/x86_64/codeready-builder/os',
        'content/dist/rhel8/8/x86_64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/x86_64/highavailability/debug',
        'content/dist/rhel8/8/x86_64/highavailability/os',
        'content/dist/rhel8/8/x86_64/highavailability/source/SRPMS',
        'content/dist/rhel8/8/x86_64/nfv/debug',
        'content/dist/rhel8/8/x86_64/nfv/os',
        'content/dist/rhel8/8/x86_64/nfv/source/SRPMS',
        'content/dist/rhel8/8/x86_64/resilientstorage/debug',
        'content/dist/rhel8/8/x86_64/resilientstorage/os',
        'content/dist/rhel8/8/x86_64/resilientstorage/source/SRPMS',
        'content/dist/rhel8/8/x86_64/rt/debug',
        'content/dist/rhel8/8/x86_64/rt/os',
        'content/dist/rhel8/8/x86_64/rt/source/SRPMS',
        'content/dist/rhel8/8/x86_64/sap-solutions/debug',
        'content/dist/rhel8/8/x86_64/sap-solutions/os',
        'content/dist/rhel8/8/x86_64/sap-solutions/source/SRPMS',
        'content/dist/rhel8/8/x86_64/sap/debug',
        'content/dist/rhel8/8/x86_64/sap/os',
        'content/dist/rhel8/8/x86_64/sap/source/SRPMS',
        'content/dist/rhel8/8/x86_64/supplementary/debug',
        'content/dist/rhel8/8/x86_64/supplementary/os',
        'content/dist/rhel8/8/x86_64/supplementary/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'mecab-0.996-2.module+el8.8.0+18436+8918dd75', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mecab-devel-0.996-2.module+el8.8.0+18436+8918dd75', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mecab-ipadic-2.7.0.20070801-16.module+el8.0.0+3898+e09bb8de', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.module+el8.0.0+3898+e09bb8de', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-8.0.32-1.module+el8.8.0+18446+fca6280e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-common-8.0.32-1.module+el8.8.0+18446+fca6280e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-devel-8.0.32-1.module+el8.8.0+18446+fca6280e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-errmsg-8.0.32-1.module+el8.8.0+18446+fca6280e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-libs-8.0.32-1.module+el8.8.0+18446+fca6280e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-server-8.0.32-1.module+el8.8.0+18446+fca6280e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-test-8.0.32-1.module+el8.8.0+18446+fca6280e', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/mysql');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mysql:8.0');
if ('8.0' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module mysql:' + module_ver);

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var module_array ( appstreams[module] ) {
      var repo_relative_urls = NULL;
      if (!empty_or_null(module_array['repo_relative_urls'])) repo_relative_urls = module_array['repo_relative_urls'];
      foreach var package_array ( module_array['pkgs'] ) {
        var reference = NULL;
        var _release = NULL;
        var sp = NULL;
        var _cpu = NULL;
        var el_string = NULL;
        var rpm_spec_vers_cmp = NULL;
        var epoch = NULL;
        var allowmaj = NULL;
        var exists_check = NULL;
        if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
        if (!empty_or_null(package_array['release'])) _release = 'RHEL' + package_array['release'];
        if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
        if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
        if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
        if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
        if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
        if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
        if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
        if (reference &&
            _release &&
            rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
            (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
            rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mysql:8.0');

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mecab / mecab-devel / mecab-ipadic / mecab-ipadic-EUCJP / mysql / etc');
}
