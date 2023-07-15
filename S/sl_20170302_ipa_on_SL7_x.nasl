#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(97515);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-2590");

  script_name(english:"Scientific Linux Security Update : ipa on SL7.x x86_64 (20170302)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security Fix(es) :

  - It was found that IdM's ca-del, ca-disable, and
    ca-enable commands did not properly check the user's
    permissions while modifying CAs in Dogtag. An
    authenticated, unauthorized attacker could use this flaw
    to delete, disable, or enable CAs causing various denial
    of service problems with certificate issuance, OCSP
    signing, and deletion of secret keys. (CVE-2017-2590)

Bug Fix(es) :

  - Previously, during an Identity Management (IdM) replica
    installation that runs on domain level '1' or higher,
    Directory Server was not configured to use TLS
    encryption. As a consequence, installing a certificate
    authority (CA) on that replica failed. Directory Server
    is now configured to use TLS encryption during the
    replica installation and as a result, the CA
    installation works as expected.

  - Previously, the Identity Management (IdM) public key
    infrastructure (PKI) component was configured to listen
    on the '::1' IPv6 localhost address. In environments
    have the the IPv6 protocol disabled, the replica
    installer was unable to retrieve the Directory Server
    certificate, and the installation failed. The default
    listening address of the PKI connector has been updated
    from the IP address to 'localhost'. As a result, the PKI
    connector now listens on the correct addresses in IPv4
    and IPv6 environments.

  - Previously, when installing a certificate authority (CA)
    on a replica, Identity Management (IdM) was unable to
    provide third-party CA certificates to the Certificate
    System CA installer. As a consequence, the installer was
    unable to connect to the remote master if the remote
    master used a third-party server certificate, and the
    installation failed. This updates applies a patch and as
    a result, installing a CA replica works as expected in
    the described situation.

  - When installing a replica, the web server service entry
    is created on the Identity Management (IdM) master and
    replicated to all IdM servers. Previously, when
    installing a replica without a certificate authority
    (CA), in certain situations the service entry was not
    replicated to the new replica on time, and the
    installation failed. The replica installer has been
    updated and now waits until the web server service entry
    is replicated. As a result, the replica installation no
    longer fails in the described situation."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1703&L=scientific-linux-errata&F=&S=&P=1161
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b9bf6656"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-admintools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-python-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python2-ipaclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python2-ipalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python2-ipaserver");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL7", reference:"ipa-admintools-4.4.0-14.el7_3.6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-client-4.4.0-14.el7_3.6")) flag++;
if (rpm_check(release:"SL7", reference:"ipa-client-common-4.4.0-14.el7_3.6")) flag++;
if (rpm_check(release:"SL7", reference:"ipa-common-4.4.0-14.el7_3.6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-debuginfo-4.4.0-14.el7_3.6")) flag++;
if (rpm_check(release:"SL7", reference:"ipa-python-compat-4.4.0-14.el7_3.6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-server-4.4.0-14.el7_3.6")) flag++;
if (rpm_check(release:"SL7", reference:"ipa-server-common-4.4.0-14.el7_3.6")) flag++;
if (rpm_check(release:"SL7", reference:"ipa-server-dns-4.4.0-14.el7_3.6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-server-trust-ad-4.4.0-14.el7_3.6")) flag++;
if (rpm_check(release:"SL7", reference:"python2-ipaclient-4.4.0-14.el7_3.6")) flag++;
if (rpm_check(release:"SL7", reference:"python2-ipalib-4.4.0-14.el7_3.6")) flag++;
if (rpm_check(release:"SL7", reference:"python2-ipaserver-4.4.0-14.el7_3.6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipa-admintools / ipa-client / ipa-client-common / ipa-common / etc");
}
