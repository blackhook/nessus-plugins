#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2154 and 
# CentOS Errata and Security Advisory 2019:2154 respectively.
#

include('compat.inc');

if (description)
{
  script_id(128365);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id(
    "CVE-2018-16391",
    "CVE-2018-16392",
    "CVE-2018-16393",
    "CVE-2018-16418",
    "CVE-2018-16419",
    "CVE-2018-16420",
    "CVE-2018-16421",
    "CVE-2018-16422",
    "CVE-2018-16423",
    "CVE-2018-16426",
    "CVE-2018-16427"
  );
  script_xref(name:"RHSA", value:"2019:2154");

  script_name(english:"CentOS 7 : opensc (CESA-2019:2154)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for opensc is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The OpenSC set of libraries and utilities provides support for working
with smart cards. OpenSC focuses on cards that support cryptographic
operations and enables their use for authentication, mail encryption,
or digital signatures.

The following packages have been upgraded to a later upstream version:
opensc (0.19.0). (BZ#1656791)

Security Fix(es) :

* opensc: Buffer overflows handling responses from Muscle Cards in
card-muscle.c:muscle_list_files() (CVE-2018-16391)

* opensc: Buffer overflows handling responses from TCOS Cards in
card-tcos.c:tcos_select_file() (CVE-2018-16392)

* opensc: Buffer overflows handling responses from Gemsafe V1
Smartcards in pkcs15-gemsafeV1.c:gemsafe_get_cert_len()
(CVE-2018-16393)

* opensc: Buffer overflow handling string concatention in tools/
util.c:util_acl_to_str() (CVE-2018-16418)

* opensc: Buffer overflow handling responses from Cryptoflex cards in
cryptoflex-tool.c:read_public_key() (CVE-2018-16419)

* opensc: Buffer overflows handling responses from ePass 2003 Cards in
card-epass2003.c:decrypt_response() (CVE-2018-16420)

* opensc: Buffer overflows handling responses from CAC Cards in
card-cac.c:cac_get_serial_nr_from_CUID() (CVE-2018-16421)

* opensc: Buffer overflow handling responses from esteid cards in
pkcs15-esteid.c:sc_pkcs15emu_esteid_init() (CVE-2018-16422)

* opensc: Double free handling responses from smartcards in libopensc/
sc.c:sc_file_set_sec_attr() (CVE-2018-16423)

* opensc: Out of bounds reads handling responses from smartcards
(CVE-2018-16427)

* opensc: Infinite recusrion handling responses from IAS-ECC cards in
card-iasecc.c:iasecc_select_file() (CVE-2018-16426)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.7 Release Notes linked from the References section.");
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006027.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8bcb4682");
  script_set_attribute(attribute:"solution", value:
"Update the affected opensc package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16423");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-16393");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:opensc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"opensc-0.19.0-3.el7")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "opensc");
}
