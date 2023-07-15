#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2022 Security Advisory ALAS2022-2022-224.
##

include('compat.inc');

if (description)
{
  script_id(168583);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/03");

  script_cve_id(
    "CVE-2016-2124",
    "CVE-2020-25717",
    "CVE-2020-25718",
    "CVE-2020-25719",
    "CVE-2020-25721",
    "CVE-2020-25722",
    "CVE-2021-3738",
    "CVE-2021-20316",
    "CVE-2021-23192",
    "CVE-2021-44141",
    "CVE-2021-44142",
    "CVE-2022-0336"
  );
  script_xref(name:"IAVA", value:"2021-A-0554-S");
  script_xref(name:"IAVA", value:"2022-A-0054-S");

  script_name(english:"Amazon Linux 2022 : samba (ALAS2022-2022-224)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2022 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of samba installed on the remote host is prior to 4.16.2-0. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2022-2022-224 advisory.

  - A flaw was found in the way samba implemented SMB1 authentication. An attacker could use this flaw to
    retrieve the plaintext password sent over the wire even if Kerberos authentication was required.
    (CVE-2016-2124)

  - A flaw was found in the way Samba maps domain users to local users. An authenticated attacker could use
    this flaw to cause possible privilege escalation. (CVE-2020-25717)

  - A flaw was found in the way samba, as an Active Directory Domain Controller, is able to support an RODC
    (read-only domain controller). This would allow an RODC to print administrator tickets. (CVE-2020-25718)

  - A flaw was found in the way Samba, as an Active Directory Domain Controller, implemented Kerberos name-
    based authentication. The Samba AD DC, could become confused about the user a ticket represents if it did
    not strictly require a Kerberos PAC and always use the SIDs found within. The result could include total
    domain compromise. (CVE-2020-25719)

  - Kerberos acceptors need easy access to stable AD identifiers (eg objectSid). Samba as an AD DC now
    provides a way for Linux applications to obtain a reliable SID (and samAccountName) in issued tickets.
    (CVE-2020-25721)

  - Multiple flaws were found in the way samba AD DC implemented access and conformance checking of stored
    data. An attacker could use this flaw to cause total domain compromise. (CVE-2020-25722)

  - A flaw was found in the way Samba handled file/directory metadata. This flaw allows an authenticated
    attacker with permissions to read or modify share metadata, to perform this operation outside of the
    share. (CVE-2021-20316)

  - A flaw was found in the way samba implemented DCE/RPC. If a client to a Samba server sent a very large
    DCE/RPC request, and chose to fragment it, an attacker could replace later fragments with their own data,
    bypassing the signature requirements. (CVE-2021-23192)

  - In DCE/RPC it is possible to share the handles (cookies for resource state) between multiple connections
    via a mechanism called 'association groups'. These handles can reference connections to our sam.ldb
    database. However while the database was correctly shared, the user credentials state was only pointed at,
    and when one connection within that association group ended, the database would be left pointing at an
    invalid 'struct session_info'. The most likely outcome here is a crash, but it is possible that the use-
    after-free could instead allow different user state to be pointed at and this might allow more privileged
    access. (CVE-2021-3738)

  - All versions of Samba prior to 4.15.5 are vulnerable to a malicious client using a server symlink to
    determine if a file or directory exists in an area of the server file system not exported under the share
    definition. SMB1 with unix extensions has to be enabled in order for this attack to succeed.
    (CVE-2021-44141)

  - The Samba vfs_fruit module uses extended file attributes (EA, xattr) to provide ...enhanced compatibility
    with Apple SMB clients and interoperability with a Netatalk 3 AFP fileserver. Samba versions prior to
    4.13.17, 4.14.12 and 4.15.5 with vfs_fruit configured allow out-of-bounds heap read and write via
    specially crafted extended file attributes. A remote attacker with write access to extended file
    attributes can execute arbitrary code with the privileges of smbd, typically root. (CVE-2021-44142)

  - The Samba AD DC includes checks when adding service principals names (SPNs) to an account to ensure that
    SPNs do not alias with those already in the database. Some of these checks are able to be bypassed if an
    account modification re-adds an SPN that was previously present on that account, such as one added when a
    computer is joined to a domain. An attacker who has the ability to write to an account can exploit this to
    perform a denial-of-service attack by adding an SPN that matches an existing service. Additionally, an
    attacker who can intercept traffic can impersonate existing services, resulting in a loss of
    confidentiality and integrity. (CVE-2022-0336)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2022/ALAS-2022-224.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2016-2124.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-25717.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-25718.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-25719.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-25721.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-25722.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-20316.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-23192.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3738.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-44141.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-44142.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0336.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update samba' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44142");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0336");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ctdb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsmbclient-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwbclient-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-samba-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-samba-dc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-client-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-common-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-common-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-dc-bind-dlz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-dc-bind-dlz-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-dc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-dc-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-dc-provision");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-krb5-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-krb5-printing-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-test-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-vfs-iouring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-vfs-iouring-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-clients-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-krb5-locator-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-modules-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2022");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "-2022")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2022", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'ctdb-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ctdb-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ctdb-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ctdb-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ctdb-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ctdb-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient-devel-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient-devel-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient-devel-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient-devel-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient-devel-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient-devel-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-dc-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-dc-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-dc-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-dc-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-dc-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-dc-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-devel-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-devel-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-devel-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-test-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-test-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-test-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-libs-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-libs-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-libs-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-libs-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-libs-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-libs-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-4.16.2-0.amzn2022.0.2', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-libs-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-libs-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-libs-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-libs-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-libs-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-libs-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-tools-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-tools-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-tools-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-tools-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-tools-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-tools-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dc-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dc-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dc-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dc-bind-dlz-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dc-bind-dlz-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dc-bind-dlz-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dc-bind-dlz-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dc-bind-dlz-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dc-bind-dlz-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dc-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dc-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dc-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dc-libs-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dc-libs-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dc-libs-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dc-libs-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dc-libs-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dc-libs-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dc-provision-4.16.2-0.amzn2022.0.2', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-debugsource-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-debugsource-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-debugsource-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-devel-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-devel-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-devel-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-krb5-printing-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-krb5-printing-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-krb5-printing-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-krb5-printing-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-krb5-printing-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-krb5-printing-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-pidl-4.16.2-0.amzn2022.0.2', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-libs-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-libs-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-libs-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-libs-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-libs-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-libs-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-vfs-iouring-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-vfs-iouring-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-vfs-iouring-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-vfs-iouring-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-clients-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-clients-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-clients-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-clients-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-clients-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-clients-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-krb5-locator-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-krb5-locator-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-krb5-locator-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-krb5-locator-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-krb5-locator-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-krb5-locator-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-modules-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-modules-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-modules-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-modules-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-modules-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-modules-debuginfo-4.16.2-0.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
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
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ctdb / ctdb-debuginfo / libsmbclient / etc");
}