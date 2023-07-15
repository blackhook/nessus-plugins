#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101432);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2017-2590"
  );

  script_name(english:"Virtuozzo 7 : ipa-admintools / ipa-client / ipa-client-common / etc (VZLSA-2017-0388)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for ipa is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat Identity Management (IdM) is a centralized authentication,
identity management, and authorization solution for both traditional
and cloud-based enterprise environments.

Security Fix(es) :

* It was found that IdM's ca-del, ca-disable, and ca-enable commands
did not properly check the user's permissions while modifying CAs in
Dogtag. An authenticated, unauthorized attacker could use this flaw to
delete, disable, or enable CAs causing various denial of service
problems with certificate issuance, OCSP signing, and deletion of
secret keys. (CVE-2017-2590)

This issue was discovered by Fraser Tweedale (Red Hat).

Bug Fix(es) :

* Previously, during an Identity Management (IdM) replica installation
that runs on domain level '1' or higher, Directory Server was not
configured to use TLS encryption. As a consequence, installing a
certificate authority (CA) on that replica failed. Directory Server is
now configured to use TLS encryption during the replica installation
and as a result, the CA installation works as expected. (BZ#1410760)

* Previously, the Identity Management (IdM) public key infrastructure
(PKI) component was configured to listen on the '::1' IPv6 localhost
address. In environments have the the IPv6 protocol disabled, the
replica installer was unable to retrieve the Directory Server
certificate, and the installation failed. The default listening
address of the PKI connector has been updated from the IP address to
'localhost'. As a result, the PKI connector now listens on the correct
addresses in IPv4 and IPv6 environments. (BZ# 1416481)

* Previously, when installing a certificate authority (CA) on a
replica, Identity Management (IdM) was unable to provide third-party
CA certificates to the Certificate System CA installer. As a
consequence, the installer was unable to connect to the remote master
if the remote master used a third-party server certificate, and the
installation failed. This updates applies a patch and as a result,
installing a CA replica works as expected in the described situation.
(BZ#1415158)

* When installing a replica, the web server service entry is created
on the Identity Management (IdM) master and replicated to all IdM
servers. Previously, when installing a replica without a certificate
authority (CA), in certain situations the service entry was not
replicated to the new replica on time, and the installation failed.
The replica installer has been updated and now waits until the web
server service entry is replicated. As a result, the replica
installation no longer fails in the described situation. (BZ#1416488)

Note that Tenable Network Security has attempted to extract the
preceding description block directly from the corresponding Red Hat
security advisory. Virtuozzo provides no description for VZLSA
advisories. Tenable has attempted to automatically clean and format
it as much as possible without introducing additional issues.");
  # http://repo.virtuozzo.com/vzlinux/announcements/json/VZLSA-2017-0388.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?acc6858e");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017-0388");
  script_set_attribute(attribute:"solution", value:
"Update the affected ipa-admintools / ipa-client / ipa-client-common / etc package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ipa-admintools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ipa-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ipa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ipa-python-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ipa-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:python2-ipaclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:python2-ipalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:python2-ipaserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:7");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Virtuozzo/release", "Host/Virtuozzo/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Virtuozzo/release");
if (isnull(release) || "Virtuozzo" >!< release) audit(AUDIT_OS_NOT, "Virtuozzo");
os_ver = pregmatch(pattern: "Virtuozzo Linux release ([0-9]+\.[0-9])(\D|$)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 7.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["ipa-admintools-4.4.0-14.vl7.6",
        "ipa-client-4.4.0-14.vl7.6",
        "ipa-client-common-4.4.0-14.vl7.6",
        "ipa-common-4.4.0-14.vl7.6",
        "ipa-python-compat-4.4.0-14.vl7.6",
        "ipa-server-4.4.0-14.vl7.6",
        "ipa-server-common-4.4.0-14.vl7.6",
        "ipa-server-dns-4.4.0-14.vl7.6",
        "ipa-server-trust-ad-4.4.0-14.vl7.6",
        "python2-ipaclient-4.4.0-14.vl7.6",
        "python2-ipalib-4.4.0-14.vl7.6",
        "python2-ipaserver-4.4.0-14.vl7.6"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-7", reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipa-admintools / ipa-client / ipa-client-common / etc");
}
