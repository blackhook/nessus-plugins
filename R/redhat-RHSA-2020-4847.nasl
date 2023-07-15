##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:4847. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142409);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id(
    "CVE-2015-9251",
    "CVE-2016-10735",
    "CVE-2018-14040",
    "CVE-2018-14042",
    "CVE-2019-8331",
    "CVE-2019-10146",
    "CVE-2019-10179",
    "CVE-2019-10221",
    "CVE-2019-11358",
    "CVE-2020-1721",
    "CVE-2020-1935",
    "CVE-2020-1938",
    "CVE-2020-11022",
    "CVE-2020-11023",
    "CVE-2020-15720",
    "CVE-2020-25715",
    "CVE-2022-25762"
  );
  script_bugtraq_id(108023, 105658, 107375);
  script_xref(name:"IAVA", value:"2019-A-0128");
  script_xref(name:"IAVA", value:"2019-A-0384");
  script_xref(name:"IAVA", value:"2020-A-0017");
  script_xref(name:"IAVA", value:"2020-A-0150");
  script_xref(name:"IAVA", value:"2020-A-0324");
  script_xref(name:"IAVA", value:"2021-A-0032");
  script_xref(name:"IAVA", value:"2021-A-0196");
  script_xref(name:"IAVA", value:"2019-A-0256-S");
  script_xref(name:"IAVA", value:"2021-A-0035-S");
  script_xref(name:"IAVA", value:"2018-A-0336-S");
  script_xref(name:"IAVA", value:"2019-A-0021-S");
  script_xref(name:"IAVA", value:"2019-A-0020-S");
  script_xref(name:"IAVA", value:"2021-A-0194-S");
  script_xref(name:"IAVB", value:"2020-B-0030");
  script_xref(name:"IAVB", value:"2020-B-0010-S");
  script_xref(name:"RHSA", value:"2020:4847");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2020-0021");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");

  script_name(english:"RHEL 8 : pki-core:10.6 and pki-deps:10.6 (RHSA-2020:4847)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:4847 advisory.

  - jquery: Cross-site scripting via cross-domain ajax requests (CVE-2015-9251)

  - bootstrap: XSS in the data-target attribute (CVE-2016-10735)

  - bootstrap: Cross-site Scripting (XSS) in the collapse data-parent attribute (CVE-2018-14040)

  - bootstrap: Cross-site Scripting (XSS) in the data-container property of tooltip (CVE-2018-14042)

  - pki-core: Reflected XSS in 'path length' constraint field in CA's Agent page (CVE-2019-10146)

  - pki-core/pki-kra: Reflected XSS in recoveryID search field at KRA's DRM agent page in authorize recovery
    tab (CVE-2019-10179)

  - pki-core: Reflected XSS in getcookies?url= endpoint in CA (CVE-2019-10221)

  - jquery: Prototype pollution in object's prototype leading to denial of service, remote code execution, or
    property injection (CVE-2019-11358)

  - bootstrap: XSS in the tooltip or popover data-template attribute (CVE-2019-8331)

  - jquery: Cross-site scripting due to improper injQuery.htmlPrefilter method (CVE-2020-11022)

  - jquery: Untrusted code execution via <option> tag in HTML passed to DOM manipulation methods
    (CVE-2020-11023)

  - pki: Dogtag's python client does not validate certificates (CVE-2020-15720)

  - pki-core: KRA vulnerable to reflected XSS via the getPk12 page (CVE-2020-1721)

  - tomcat: Mishandling of Transfer-Encoding header allows for HTTP request smuggling (CVE-2020-1935)

  - tomcat: Apache Tomcat AJP File Read/Inclusion Vulnerability (CVE-2020-1938)

  - pki-core: XSS in the certificate search results (CVE-2020-25715)

  - tomcat: request mixup (CVE-2022-25762)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2015-9251");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2016-10735");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-14040");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-14042");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8331");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10146");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10179");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10221");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11358");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1721");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1935");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1938");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11022");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11023");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-15720");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25715");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-25762");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:4847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1399546");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1601614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1601617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1668097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1686454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1695901");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1701972");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1710171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1732565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1777579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1806398");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1806835");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1828406");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1850004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1855273");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1891016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2085304");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-25762");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-1938");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(79, 226, 285, 295, 444);

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-collections");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-net");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bea-stax-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-fastinfoset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxb-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxb-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxb-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxb-txw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jackson-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jackson-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jackson-databind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jackson-jaxrs-json-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jackson-jaxrs-providers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jackson-module-jaxb-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-httpclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:javassist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:javassist-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jss-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ldapjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ldapjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-base-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-kra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-servlet-4.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-servlet-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-symkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-nss-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:relaxngDatatype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slf4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slf4j-jdk14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:stax-ex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcatjss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:velocity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xalan-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xmlstreambuffer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xsom");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  'pki-deps:10.6': [
    {
      'repo_relative_urls': [
        'content/aus/rhel8/8.4/x86_64/appstream/debug',
        'content/aus/rhel8/8.4/x86_64/appstream/os',
        'content/aus/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/aus/rhel8/8.4/x86_64/baseos/debug',
        'content/aus/rhel8/8.4/x86_64/baseos/os',
        'content/aus/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/aarch64/appstream/debug',
        'content/e4s/rhel8/8.4/aarch64/appstream/os',
        'content/e4s/rhel8/8.4/aarch64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.4/aarch64/baseos/debug',
        'content/e4s/rhel8/8.4/aarch64/baseos/os',
        'content/e4s/rhel8/8.4/aarch64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/ppc64le/appstream/debug',
        'content/e4s/rhel8/8.4/ppc64le/appstream/os',
        'content/e4s/rhel8/8.4/ppc64le/appstream/source/SRPMS',
        'content/e4s/rhel8/8.4/ppc64le/baseos/debug',
        'content/e4s/rhel8/8.4/ppc64le/baseos/os',
        'content/e4s/rhel8/8.4/ppc64le/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/ppc64le/highavailability/debug',
        'content/e4s/rhel8/8.4/ppc64le/highavailability/os',
        'content/e4s/rhel8/8.4/ppc64le/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.4/ppc64le/sap-solutions/debug',
        'content/e4s/rhel8/8.4/ppc64le/sap-solutions/os',
        'content/e4s/rhel8/8.4/ppc64le/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.4/ppc64le/sap/debug',
        'content/e4s/rhel8/8.4/ppc64le/sap/os',
        'content/e4s/rhel8/8.4/ppc64le/sap/source/SRPMS',
        'content/e4s/rhel8/8.4/s390x/appstream/debug',
        'content/e4s/rhel8/8.4/s390x/appstream/os',
        'content/e4s/rhel8/8.4/s390x/appstream/source/SRPMS',
        'content/e4s/rhel8/8.4/s390x/baseos/debug',
        'content/e4s/rhel8/8.4/s390x/baseos/os',
        'content/e4s/rhel8/8.4/s390x/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/appstream/debug',
        'content/e4s/rhel8/8.4/x86_64/appstream/os',
        'content/e4s/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/baseos/debug',
        'content/e4s/rhel8/8.4/x86_64/baseos/os',
        'content/e4s/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/highavailability/debug',
        'content/e4s/rhel8/8.4/x86_64/highavailability/os',
        'content/e4s/rhel8/8.4/x86_64/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/nfv/debug',
        'content/e4s/rhel8/8.4/x86_64/nfv/os',
        'content/e4s/rhel8/8.4/x86_64/nfv/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/sap-solutions/debug',
        'content/e4s/rhel8/8.4/x86_64/sap-solutions/os',
        'content/e4s/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/sap/debug',
        'content/e4s/rhel8/8.4/x86_64/sap/os',
        'content/e4s/rhel8/8.4/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/appstream/debug',
        'content/eus/rhel8/8.4/aarch64/appstream/os',
        'content/eus/rhel8/8.4/aarch64/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/baseos/debug',
        'content/eus/rhel8/8.4/aarch64/baseos/os',
        'content/eus/rhel8/8.4/aarch64/baseos/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/codeready-builder/debug',
        'content/eus/rhel8/8.4/aarch64/codeready-builder/os',
        'content/eus/rhel8/8.4/aarch64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/highavailability/debug',
        'content/eus/rhel8/8.4/aarch64/highavailability/os',
        'content/eus/rhel8/8.4/aarch64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/supplementary/debug',
        'content/eus/rhel8/8.4/aarch64/supplementary/os',
        'content/eus/rhel8/8.4/aarch64/supplementary/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/appstream/debug',
        'content/eus/rhel8/8.4/ppc64le/appstream/os',
        'content/eus/rhel8/8.4/ppc64le/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/baseos/debug',
        'content/eus/rhel8/8.4/ppc64le/baseos/os',
        'content/eus/rhel8/8.4/ppc64le/baseos/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/codeready-builder/debug',
        'content/eus/rhel8/8.4/ppc64le/codeready-builder/os',
        'content/eus/rhel8/8.4/ppc64le/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/highavailability/debug',
        'content/eus/rhel8/8.4/ppc64le/highavailability/os',
        'content/eus/rhel8/8.4/ppc64le/highavailability/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/resilientstorage/debug',
        'content/eus/rhel8/8.4/ppc64le/resilientstorage/os',
        'content/eus/rhel8/8.4/ppc64le/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/sap-solutions/debug',
        'content/eus/rhel8/8.4/ppc64le/sap-solutions/os',
        'content/eus/rhel8/8.4/ppc64le/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/sap/debug',
        'content/eus/rhel8/8.4/ppc64le/sap/os',
        'content/eus/rhel8/8.4/ppc64le/sap/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/supplementary/debug',
        'content/eus/rhel8/8.4/ppc64le/supplementary/os',
        'content/eus/rhel8/8.4/ppc64le/supplementary/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/appstream/debug',
        'content/eus/rhel8/8.4/s390x/appstream/os',
        'content/eus/rhel8/8.4/s390x/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/baseos/debug',
        'content/eus/rhel8/8.4/s390x/baseos/os',
        'content/eus/rhel8/8.4/s390x/baseos/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/codeready-builder/debug',
        'content/eus/rhel8/8.4/s390x/codeready-builder/os',
        'content/eus/rhel8/8.4/s390x/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/highavailability/debug',
        'content/eus/rhel8/8.4/s390x/highavailability/os',
        'content/eus/rhel8/8.4/s390x/highavailability/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/resilientstorage/debug',
        'content/eus/rhel8/8.4/s390x/resilientstorage/os',
        'content/eus/rhel8/8.4/s390x/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/sap/debug',
        'content/eus/rhel8/8.4/s390x/sap/os',
        'content/eus/rhel8/8.4/s390x/sap/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/supplementary/debug',
        'content/eus/rhel8/8.4/s390x/supplementary/os',
        'content/eus/rhel8/8.4/s390x/supplementary/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/appstream/debug',
        'content/eus/rhel8/8.4/x86_64/appstream/os',
        'content/eus/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/baseos/debug',
        'content/eus/rhel8/8.4/x86_64/baseos/os',
        'content/eus/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/codeready-builder/debug',
        'content/eus/rhel8/8.4/x86_64/codeready-builder/os',
        'content/eus/rhel8/8.4/x86_64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/highavailability/debug',
        'content/eus/rhel8/8.4/x86_64/highavailability/os',
        'content/eus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/resilientstorage/debug',
        'content/eus/rhel8/8.4/x86_64/resilientstorage/os',
        'content/eus/rhel8/8.4/x86_64/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/sap-solutions/debug',
        'content/eus/rhel8/8.4/x86_64/sap-solutions/os',
        'content/eus/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/sap/debug',
        'content/eus/rhel8/8.4/x86_64/sap/os',
        'content/eus/rhel8/8.4/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/supplementary/debug',
        'content/eus/rhel8/8.4/x86_64/supplementary/os',
        'content/eus/rhel8/8.4/x86_64/supplementary/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/appstream/debug',
        'content/tus/rhel8/8.4/x86_64/appstream/os',
        'content/tus/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/baseos/debug',
        'content/tus/rhel8/8.4/x86_64/baseos/os',
        'content/tus/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/highavailability/debug',
        'content/tus/rhel8/8.4/x86_64/highavailability/os',
        'content/tus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/nfv/debug',
        'content/tus/rhel8/8.4/x86_64/nfv/os',
        'content/tus/rhel8/8.4/x86_64/nfv/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/rt/debug',
        'content/tus/rhel8/8.4/x86_64/rt/os',
        'content/tus/rhel8/8.4/x86_64/rt/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'apache-commons-collections-3.2.2-10.module+el8.1.0+3366+6dfb954c', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-lang-2.6-21.module+el8.1.0+3366+6dfb954c', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-net-3.6-3.module+el8.3.0+6805+72837426', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'bea-stax-api-1.2.0-16.module+el8.1.0+3366+6dfb954c', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'glassfish-fastinfoset-1.2.13-9.module+el8.1.0+3366+6dfb954c', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'glassfish-jaxb-api-2.2.12-8.module+el8.1.0+3366+6dfb954c', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'glassfish-jaxb-core-2.2.11-11.module+el8.1.0+3366+6dfb954c', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'glassfish-jaxb-runtime-2.2.11-11.module+el8.1.0+3366+6dfb954c', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'glassfish-jaxb-txw2-2.2.11-11.module+el8.1.0+3366+6dfb954c', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jackson-annotations-2.10.0-1.module+el8.2.0+5059+3eb3af25', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jackson-core-2.10.0-1.module+el8.2.0+5059+3eb3af25', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jackson-databind-2.10.0-1.module+el8.2.0+5059+3eb3af25', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jackson-jaxrs-json-provider-2.9.9-1.module+el8.1.0+3832+9784644d', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jackson-jaxrs-providers-2.9.9-1.module+el8.1.0+3832+9784644d', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jackson-module-jaxb-annotations-2.7.6-4.module+el8.1.0+3366+6dfb954c', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jakarta-commons-httpclient-3.1-28.module+el8.1.0+3366+6dfb954c', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'javassist-3.18.1-8.module+el8.1.0+3366+6dfb954c', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'javassist-javadoc-3.18.1-8.module+el8.1.0+3366+6dfb954c', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'pki-servlet-4.0-api-9.0.30-1.module+el8.3.0+6730+8f9c6254', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'pki-servlet-engine-9.0.30-1.module+el8.3.0+6730+8f9c6254', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'python-nss-doc-1.0.1-10.module+el8.1.0+3366+6dfb954c', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-nss-1.0.1-10.module+el8.1.0+3366+6dfb954c', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'relaxngDatatype-2011.1-7.module+el8.1.0+3366+6dfb954c', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'resteasy-3.0.26-3.module+el8.2.0+5723+4574fbff', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'slf4j-1.7.25-4.module+el8.1.0+3366+6dfb954c', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'slf4j-jdk14-1.7.25-4.module+el8.1.0+3366+6dfb954c', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'stax-ex-1.7.7-8.module+el8.2.0+5723+4574fbff', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'velocity-1.7-24.module+el8.1.0+3366+6dfb954c', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'xalan-j2-2.7.1-38.module+el8.1.0+3366+6dfb954c', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'xerces-j2-2.11.0-34.module+el8.1.0+3366+6dfb954c', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'xml-commons-apis-1.4.01-25.module+el8.1.0+3366+6dfb954c', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'xml-commons-resolver-1.2-26.module+el8.1.0+3366+6dfb954c', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'xmlstreambuffer-1.5.4-8.module+el8.2.0+5723+4574fbff', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'xsom-0-19.20110809svn.module+el8.1.0+3366+6dfb954c', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE}
      ]
    },
    {
      'repo_relative_urls': [
        'content/aus/rhel8/8.6/x86_64/appstream/debug',
        'content/aus/rhel8/8.6/x86_64/appstream/os',
        'content/aus/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/aus/rhel8/8.6/x86_64/baseos/debug',
        'content/aus/rhel8/8.6/x86_64/baseos/os',
        'content/aus/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/appstream/debug',
        'content/e4s/rhel8/8.6/ppc64le/appstream/os',
        'content/e4s/rhel8/8.6/ppc64le/appstream/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/baseos/debug',
        'content/e4s/rhel8/8.6/ppc64le/baseos/os',
        'content/e4s/rhel8/8.6/ppc64le/baseos/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/highavailability/debug',
        'content/e4s/rhel8/8.6/ppc64le/highavailability/os',
        'content/e4s/rhel8/8.6/ppc64le/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/sap-solutions/debug',
        'content/e4s/rhel8/8.6/ppc64le/sap-solutions/os',
        'content/e4s/rhel8/8.6/ppc64le/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/sap/debug',
        'content/e4s/rhel8/8.6/ppc64le/sap/os',
        'content/e4s/rhel8/8.6/ppc64le/sap/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/appstream/debug',
        'content/e4s/rhel8/8.6/x86_64/appstream/os',
        'content/e4s/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/baseos/debug',
        'content/e4s/rhel8/8.6/x86_64/baseos/os',
        'content/e4s/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/highavailability/debug',
        'content/e4s/rhel8/8.6/x86_64/highavailability/os',
        'content/e4s/rhel8/8.6/x86_64/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/sap-solutions/debug',
        'content/e4s/rhel8/8.6/x86_64/sap-solutions/os',
        'content/e4s/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/sap/debug',
        'content/e4s/rhel8/8.6/x86_64/sap/os',
        'content/e4s/rhel8/8.6/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/appstream/debug',
        'content/eus/rhel8/8.6/aarch64/appstream/os',
        'content/eus/rhel8/8.6/aarch64/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/baseos/debug',
        'content/eus/rhel8/8.6/aarch64/baseos/os',
        'content/eus/rhel8/8.6/aarch64/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/codeready-builder/debug',
        'content/eus/rhel8/8.6/aarch64/codeready-builder/os',
        'content/eus/rhel8/8.6/aarch64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/highavailability/debug',
        'content/eus/rhel8/8.6/aarch64/highavailability/os',
        'content/eus/rhel8/8.6/aarch64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/supplementary/debug',
        'content/eus/rhel8/8.6/aarch64/supplementary/os',
        'content/eus/rhel8/8.6/aarch64/supplementary/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/appstream/debug',
        'content/eus/rhel8/8.6/ppc64le/appstream/os',
        'content/eus/rhel8/8.6/ppc64le/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/baseos/debug',
        'content/eus/rhel8/8.6/ppc64le/baseos/os',
        'content/eus/rhel8/8.6/ppc64le/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/codeready-builder/debug',
        'content/eus/rhel8/8.6/ppc64le/codeready-builder/os',
        'content/eus/rhel8/8.6/ppc64le/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/highavailability/debug',
        'content/eus/rhel8/8.6/ppc64le/highavailability/os',
        'content/eus/rhel8/8.6/ppc64le/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/resilientstorage/debug',
        'content/eus/rhel8/8.6/ppc64le/resilientstorage/os',
        'content/eus/rhel8/8.6/ppc64le/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/sap-solutions/debug',
        'content/eus/rhel8/8.6/ppc64le/sap-solutions/os',
        'content/eus/rhel8/8.6/ppc64le/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/sap/debug',
        'content/eus/rhel8/8.6/ppc64le/sap/os',
        'content/eus/rhel8/8.6/ppc64le/sap/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/supplementary/debug',
        'content/eus/rhel8/8.6/ppc64le/supplementary/os',
        'content/eus/rhel8/8.6/ppc64le/supplementary/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/appstream/debug',
        'content/eus/rhel8/8.6/s390x/appstream/os',
        'content/eus/rhel8/8.6/s390x/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/baseos/debug',
        'content/eus/rhel8/8.6/s390x/baseos/os',
        'content/eus/rhel8/8.6/s390x/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/codeready-builder/debug',
        'content/eus/rhel8/8.6/s390x/codeready-builder/os',
        'content/eus/rhel8/8.6/s390x/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/highavailability/debug',
        'content/eus/rhel8/8.6/s390x/highavailability/os',
        'content/eus/rhel8/8.6/s390x/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/resilientstorage/debug',
        'content/eus/rhel8/8.6/s390x/resilientstorage/os',
        'content/eus/rhel8/8.6/s390x/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/sap/debug',
        'content/eus/rhel8/8.6/s390x/sap/os',
        'content/eus/rhel8/8.6/s390x/sap/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/supplementary/debug',
        'content/eus/rhel8/8.6/s390x/supplementary/os',
        'content/eus/rhel8/8.6/s390x/supplementary/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/appstream/debug',
        'content/eus/rhel8/8.6/x86_64/appstream/os',
        'content/eus/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/baseos/debug',
        'content/eus/rhel8/8.6/x86_64/baseos/os',
        'content/eus/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/codeready-builder/debug',
        'content/eus/rhel8/8.6/x86_64/codeready-builder/os',
        'content/eus/rhel8/8.6/x86_64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/highavailability/debug',
        'content/eus/rhel8/8.6/x86_64/highavailability/os',
        'content/eus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/resilientstorage/debug',
        'content/eus/rhel8/8.6/x86_64/resilientstorage/os',
        'content/eus/rhel8/8.6/x86_64/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/sap-solutions/debug',
        'content/eus/rhel8/8.6/x86_64/sap-solutions/os',
        'content/eus/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/sap/debug',
        'content/eus/rhel8/8.6/x86_64/sap/os',
        'content/eus/rhel8/8.6/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/supplementary/debug',
        'content/eus/rhel8/8.6/x86_64/supplementary/os',
        'content/eus/rhel8/8.6/x86_64/supplementary/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/appstream/debug',
        'content/tus/rhel8/8.6/x86_64/appstream/os',
        'content/tus/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/baseos/debug',
        'content/tus/rhel8/8.6/x86_64/baseos/os',
        'content/tus/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/highavailability/debug',
        'content/tus/rhel8/8.6/x86_64/highavailability/os',
        'content/tus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/rt/os',
        'content/tus/rhel8/8.6/x86_64/rt/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'apache-commons-collections-3.2.2-10.module+el8.1.0+3366+6dfb954c', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-lang-2.6-21.module+el8.1.0+3366+6dfb954c', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-net-3.6-3.module+el8.3.0+6805+72837426', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'bea-stax-api-1.2.0-16.module+el8.1.0+3366+6dfb954c', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'glassfish-fastinfoset-1.2.13-9.module+el8.1.0+3366+6dfb954c', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'glassfish-jaxb-api-2.2.12-8.module+el8.1.0+3366+6dfb954c', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'glassfish-jaxb-core-2.2.11-11.module+el8.1.0+3366+6dfb954c', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'glassfish-jaxb-runtime-2.2.11-11.module+el8.1.0+3366+6dfb954c', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'glassfish-jaxb-txw2-2.2.11-11.module+el8.1.0+3366+6dfb954c', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jackson-annotations-2.10.0-1.module+el8.2.0+5059+3eb3af25', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jackson-core-2.10.0-1.module+el8.2.0+5059+3eb3af25', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jackson-databind-2.10.0-1.module+el8.2.0+5059+3eb3af25', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jackson-jaxrs-json-provider-2.9.9-1.module+el8.1.0+3832+9784644d', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jackson-jaxrs-providers-2.9.9-1.module+el8.1.0+3832+9784644d', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jackson-module-jaxb-annotations-2.7.6-4.module+el8.1.0+3366+6dfb954c', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jakarta-commons-httpclient-3.1-28.module+el8.1.0+3366+6dfb954c', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'javassist-3.18.1-8.module+el8.1.0+3366+6dfb954c', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'javassist-javadoc-3.18.1-8.module+el8.1.0+3366+6dfb954c', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'pki-servlet-4.0-api-9.0.30-1.module+el8.3.0+6730+8f9c6254', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'pki-servlet-engine-9.0.30-1.module+el8.3.0+6730+8f9c6254', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'python-nss-doc-1.0.1-10.module+el8.1.0+3366+6dfb954c', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-nss-1.0.1-10.module+el8.1.0+3366+6dfb954c', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'relaxngDatatype-2011.1-7.module+el8.1.0+3366+6dfb954c', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'resteasy-3.0.26-3.module+el8.2.0+5723+4574fbff', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'slf4j-1.7.25-4.module+el8.1.0+3366+6dfb954c', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'slf4j-jdk14-1.7.25-4.module+el8.1.0+3366+6dfb954c', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'stax-ex-1.7.7-8.module+el8.2.0+5723+4574fbff', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'velocity-1.7-24.module+el8.1.0+3366+6dfb954c', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'xalan-j2-2.7.1-38.module+el8.1.0+3366+6dfb954c', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'xerces-j2-2.11.0-34.module+el8.1.0+3366+6dfb954c', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'xml-commons-apis-1.4.01-25.module+el8.1.0+3366+6dfb954c', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'xml-commons-resolver-1.2-26.module+el8.1.0+3366+6dfb954c', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'xmlstreambuffer-1.5.4-8.module+el8.2.0+5723+4574fbff', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'xsom-0-19.20110809svn.module+el8.1.0+3366+6dfb954c', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE}
      ]
    },
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
        {'reference':'apache-commons-collections-3.2.2-10.module+el8.1.0+3366+6dfb954c', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-lang-2.6-21.module+el8.1.0+3366+6dfb954c', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-net-3.6-3.module+el8.3.0+6805+72837426', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'bea-stax-api-1.2.0-16.module+el8.1.0+3366+6dfb954c', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'glassfish-fastinfoset-1.2.13-9.module+el8.1.0+3366+6dfb954c', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'glassfish-jaxb-api-2.2.12-8.module+el8.1.0+3366+6dfb954c', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'glassfish-jaxb-core-2.2.11-11.module+el8.1.0+3366+6dfb954c', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'glassfish-jaxb-runtime-2.2.11-11.module+el8.1.0+3366+6dfb954c', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'glassfish-jaxb-txw2-2.2.11-11.module+el8.1.0+3366+6dfb954c', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jackson-annotations-2.10.0-1.module+el8.2.0+5059+3eb3af25', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jackson-core-2.10.0-1.module+el8.2.0+5059+3eb3af25', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jackson-databind-2.10.0-1.module+el8.2.0+5059+3eb3af25', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jackson-jaxrs-json-provider-2.9.9-1.module+el8.1.0+3832+9784644d', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jackson-jaxrs-providers-2.9.9-1.module+el8.1.0+3832+9784644d', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jackson-module-jaxb-annotations-2.7.6-4.module+el8.1.0+3366+6dfb954c', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jakarta-commons-httpclient-3.1-28.module+el8.1.0+3366+6dfb954c', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'javassist-3.18.1-8.module+el8.1.0+3366+6dfb954c', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'javassist-javadoc-3.18.1-8.module+el8.1.0+3366+6dfb954c', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'pki-servlet-4.0-api-9.0.30-1.module+el8.3.0+6730+8f9c6254', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'pki-servlet-engine-9.0.30-1.module+el8.3.0+6730+8f9c6254', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'python-nss-doc-1.0.1-10.module+el8.1.0+3366+6dfb954c', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-nss-1.0.1-10.module+el8.1.0+3366+6dfb954c', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'relaxngDatatype-2011.1-7.module+el8.1.0+3366+6dfb954c', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'resteasy-3.0.26-3.module+el8.2.0+5723+4574fbff', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'slf4j-1.7.25-4.module+el8.1.0+3366+6dfb954c', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'slf4j-jdk14-1.7.25-4.module+el8.1.0+3366+6dfb954c', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'stax-ex-1.7.7-8.module+el8.2.0+5723+4574fbff', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'velocity-1.7-24.module+el8.1.0+3366+6dfb954c', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'xalan-j2-2.7.1-38.module+el8.1.0+3366+6dfb954c', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'xerces-j2-2.11.0-34.module+el8.1.0+3366+6dfb954c', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'xml-commons-apis-1.4.01-25.module+el8.1.0+3366+6dfb954c', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'xml-commons-resolver-1.2-26.module+el8.1.0+3366+6dfb954c', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'xmlstreambuffer-1.5.4-8.module+el8.2.0+5723+4574fbff', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'xsom-0-19.20110809svn.module+el8.1.0+3366+6dfb954c', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE}
      ]
    }
  ],
  'pki-core:10.6': [
    {
      'repo_relative_urls': [
        'content/aus/rhel8/8.4/x86_64/appstream/debug',
        'content/aus/rhel8/8.4/x86_64/appstream/os',
        'content/aus/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/aus/rhel8/8.4/x86_64/baseos/debug',
        'content/aus/rhel8/8.4/x86_64/baseos/os',
        'content/aus/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/aarch64/appstream/debug',
        'content/e4s/rhel8/8.4/aarch64/appstream/os',
        'content/e4s/rhel8/8.4/aarch64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.4/aarch64/baseos/debug',
        'content/e4s/rhel8/8.4/aarch64/baseos/os',
        'content/e4s/rhel8/8.4/aarch64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/ppc64le/appstream/debug',
        'content/e4s/rhel8/8.4/ppc64le/appstream/os',
        'content/e4s/rhel8/8.4/ppc64le/appstream/source/SRPMS',
        'content/e4s/rhel8/8.4/ppc64le/baseos/debug',
        'content/e4s/rhel8/8.4/ppc64le/baseos/os',
        'content/e4s/rhel8/8.4/ppc64le/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/ppc64le/highavailability/debug',
        'content/e4s/rhel8/8.4/ppc64le/highavailability/os',
        'content/e4s/rhel8/8.4/ppc64le/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.4/ppc64le/sap-solutions/debug',
        'content/e4s/rhel8/8.4/ppc64le/sap-solutions/os',
        'content/e4s/rhel8/8.4/ppc64le/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.4/ppc64le/sap/debug',
        'content/e4s/rhel8/8.4/ppc64le/sap/os',
        'content/e4s/rhel8/8.4/ppc64le/sap/source/SRPMS',
        'content/e4s/rhel8/8.4/s390x/appstream/debug',
        'content/e4s/rhel8/8.4/s390x/appstream/os',
        'content/e4s/rhel8/8.4/s390x/appstream/source/SRPMS',
        'content/e4s/rhel8/8.4/s390x/baseos/debug',
        'content/e4s/rhel8/8.4/s390x/baseos/os',
        'content/e4s/rhel8/8.4/s390x/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/appstream/debug',
        'content/e4s/rhel8/8.4/x86_64/appstream/os',
        'content/e4s/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/baseos/debug',
        'content/e4s/rhel8/8.4/x86_64/baseos/os',
        'content/e4s/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/highavailability/debug',
        'content/e4s/rhel8/8.4/x86_64/highavailability/os',
        'content/e4s/rhel8/8.4/x86_64/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/nfv/debug',
        'content/e4s/rhel8/8.4/x86_64/nfv/os',
        'content/e4s/rhel8/8.4/x86_64/nfv/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/sap-solutions/debug',
        'content/e4s/rhel8/8.4/x86_64/sap-solutions/os',
        'content/e4s/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/sap/debug',
        'content/e4s/rhel8/8.4/x86_64/sap/os',
        'content/e4s/rhel8/8.4/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/appstream/debug',
        'content/eus/rhel8/8.4/aarch64/appstream/os',
        'content/eus/rhel8/8.4/aarch64/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/baseos/debug',
        'content/eus/rhel8/8.4/aarch64/baseos/os',
        'content/eus/rhel8/8.4/aarch64/baseos/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/codeready-builder/debug',
        'content/eus/rhel8/8.4/aarch64/codeready-builder/os',
        'content/eus/rhel8/8.4/aarch64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/highavailability/debug',
        'content/eus/rhel8/8.4/aarch64/highavailability/os',
        'content/eus/rhel8/8.4/aarch64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/supplementary/debug',
        'content/eus/rhel8/8.4/aarch64/supplementary/os',
        'content/eus/rhel8/8.4/aarch64/supplementary/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/appstream/debug',
        'content/eus/rhel8/8.4/ppc64le/appstream/os',
        'content/eus/rhel8/8.4/ppc64le/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/baseos/debug',
        'content/eus/rhel8/8.4/ppc64le/baseos/os',
        'content/eus/rhel8/8.4/ppc64le/baseos/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/codeready-builder/debug',
        'content/eus/rhel8/8.4/ppc64le/codeready-builder/os',
        'content/eus/rhel8/8.4/ppc64le/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/highavailability/debug',
        'content/eus/rhel8/8.4/ppc64le/highavailability/os',
        'content/eus/rhel8/8.4/ppc64le/highavailability/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/resilientstorage/debug',
        'content/eus/rhel8/8.4/ppc64le/resilientstorage/os',
        'content/eus/rhel8/8.4/ppc64le/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/sap-solutions/debug',
        'content/eus/rhel8/8.4/ppc64le/sap-solutions/os',
        'content/eus/rhel8/8.4/ppc64le/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/sap/debug',
        'content/eus/rhel8/8.4/ppc64le/sap/os',
        'content/eus/rhel8/8.4/ppc64le/sap/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/supplementary/debug',
        'content/eus/rhel8/8.4/ppc64le/supplementary/os',
        'content/eus/rhel8/8.4/ppc64le/supplementary/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/appstream/debug',
        'content/eus/rhel8/8.4/s390x/appstream/os',
        'content/eus/rhel8/8.4/s390x/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/baseos/debug',
        'content/eus/rhel8/8.4/s390x/baseos/os',
        'content/eus/rhel8/8.4/s390x/baseos/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/codeready-builder/debug',
        'content/eus/rhel8/8.4/s390x/codeready-builder/os',
        'content/eus/rhel8/8.4/s390x/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/highavailability/debug',
        'content/eus/rhel8/8.4/s390x/highavailability/os',
        'content/eus/rhel8/8.4/s390x/highavailability/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/resilientstorage/debug',
        'content/eus/rhel8/8.4/s390x/resilientstorage/os',
        'content/eus/rhel8/8.4/s390x/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/sap/debug',
        'content/eus/rhel8/8.4/s390x/sap/os',
        'content/eus/rhel8/8.4/s390x/sap/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/supplementary/debug',
        'content/eus/rhel8/8.4/s390x/supplementary/os',
        'content/eus/rhel8/8.4/s390x/supplementary/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/appstream/debug',
        'content/eus/rhel8/8.4/x86_64/appstream/os',
        'content/eus/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/baseos/debug',
        'content/eus/rhel8/8.4/x86_64/baseos/os',
        'content/eus/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/codeready-builder/debug',
        'content/eus/rhel8/8.4/x86_64/codeready-builder/os',
        'content/eus/rhel8/8.4/x86_64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/highavailability/debug',
        'content/eus/rhel8/8.4/x86_64/highavailability/os',
        'content/eus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/resilientstorage/debug',
        'content/eus/rhel8/8.4/x86_64/resilientstorage/os',
        'content/eus/rhel8/8.4/x86_64/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/sap-solutions/debug',
        'content/eus/rhel8/8.4/x86_64/sap-solutions/os',
        'content/eus/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/sap/debug',
        'content/eus/rhel8/8.4/x86_64/sap/os',
        'content/eus/rhel8/8.4/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/supplementary/debug',
        'content/eus/rhel8/8.4/x86_64/supplementary/os',
        'content/eus/rhel8/8.4/x86_64/supplementary/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/appstream/debug',
        'content/tus/rhel8/8.4/x86_64/appstream/os',
        'content/tus/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/baseos/debug',
        'content/tus/rhel8/8.4/x86_64/baseos/os',
        'content/tus/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/highavailability/debug',
        'content/tus/rhel8/8.4/x86_64/highavailability/os',
        'content/tus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/nfv/debug',
        'content/tus/rhel8/8.4/x86_64/nfv/os',
        'content/tus/rhel8/8.4/x86_64/nfv/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/rt/debug',
        'content/tus/rhel8/8.4/x86_64/rt/os',
        'content/tus/rhel8/8.4/x86_64/rt/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'jss-4.7.3-1.module+el8.3.0+8058+d5cd4219', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jss-javadoc-4.7.3-1.module+el8.3.0+8058+d5cd4219', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ldapjdk-4.22.0-1.module+el8.3.0+6784+6e1e4c62', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ldapjdk-javadoc-4.22.0-1.module+el8.3.0+6784+6e1e4c62', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'pki-base-10.9.4-1.module+el8.3.0+8058+d5cd4219', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'pki-base-java-10.9.4-1.module+el8.3.0+8058+d5cd4219', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'pki-ca-10.9.4-1.module+el8.3.0+8058+d5cd4219', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'pki-kra-10.9.4-1.module+el8.3.0+8058+d5cd4219', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'pki-server-10.9.4-1.module+el8.3.0+8058+d5cd4219', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'pki-symkey-10.9.4-1.module+el8.3.0+8058+d5cd4219', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'pki-tools-10.9.4-1.module+el8.3.0+8058+d5cd4219', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-pki-10.9.4-1.module+el8.3.0+8058+d5cd4219', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'tomcatjss-7.5.0-1.module+el8.3.0+7355+c59bcbd9', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE}
      ]
    },
    {
      'repo_relative_urls': [
        'content/aus/rhel8/8.6/x86_64/appstream/debug',
        'content/aus/rhel8/8.6/x86_64/appstream/os',
        'content/aus/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/aus/rhel8/8.6/x86_64/baseos/debug',
        'content/aus/rhel8/8.6/x86_64/baseos/os',
        'content/aus/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/appstream/debug',
        'content/e4s/rhel8/8.6/ppc64le/appstream/os',
        'content/e4s/rhel8/8.6/ppc64le/appstream/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/baseos/debug',
        'content/e4s/rhel8/8.6/ppc64le/baseos/os',
        'content/e4s/rhel8/8.6/ppc64le/baseos/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/highavailability/debug',
        'content/e4s/rhel8/8.6/ppc64le/highavailability/os',
        'content/e4s/rhel8/8.6/ppc64le/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/sap-solutions/debug',
        'content/e4s/rhel8/8.6/ppc64le/sap-solutions/os',
        'content/e4s/rhel8/8.6/ppc64le/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/sap/debug',
        'content/e4s/rhel8/8.6/ppc64le/sap/os',
        'content/e4s/rhel8/8.6/ppc64le/sap/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/appstream/debug',
        'content/e4s/rhel8/8.6/x86_64/appstream/os',
        'content/e4s/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/baseos/debug',
        'content/e4s/rhel8/8.6/x86_64/baseos/os',
        'content/e4s/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/highavailability/debug',
        'content/e4s/rhel8/8.6/x86_64/highavailability/os',
        'content/e4s/rhel8/8.6/x86_64/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/sap-solutions/debug',
        'content/e4s/rhel8/8.6/x86_64/sap-solutions/os',
        'content/e4s/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/sap/debug',
        'content/e4s/rhel8/8.6/x86_64/sap/os',
        'content/e4s/rhel8/8.6/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/appstream/debug',
        'content/eus/rhel8/8.6/aarch64/appstream/os',
        'content/eus/rhel8/8.6/aarch64/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/baseos/debug',
        'content/eus/rhel8/8.6/aarch64/baseos/os',
        'content/eus/rhel8/8.6/aarch64/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/codeready-builder/debug',
        'content/eus/rhel8/8.6/aarch64/codeready-builder/os',
        'content/eus/rhel8/8.6/aarch64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/highavailability/debug',
        'content/eus/rhel8/8.6/aarch64/highavailability/os',
        'content/eus/rhel8/8.6/aarch64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/supplementary/debug',
        'content/eus/rhel8/8.6/aarch64/supplementary/os',
        'content/eus/rhel8/8.6/aarch64/supplementary/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/appstream/debug',
        'content/eus/rhel8/8.6/ppc64le/appstream/os',
        'content/eus/rhel8/8.6/ppc64le/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/baseos/debug',
        'content/eus/rhel8/8.6/ppc64le/baseos/os',
        'content/eus/rhel8/8.6/ppc64le/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/codeready-builder/debug',
        'content/eus/rhel8/8.6/ppc64le/codeready-builder/os',
        'content/eus/rhel8/8.6/ppc64le/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/highavailability/debug',
        'content/eus/rhel8/8.6/ppc64le/highavailability/os',
        'content/eus/rhel8/8.6/ppc64le/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/resilientstorage/debug',
        'content/eus/rhel8/8.6/ppc64le/resilientstorage/os',
        'content/eus/rhel8/8.6/ppc64le/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/sap-solutions/debug',
        'content/eus/rhel8/8.6/ppc64le/sap-solutions/os',
        'content/eus/rhel8/8.6/ppc64le/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/sap/debug',
        'content/eus/rhel8/8.6/ppc64le/sap/os',
        'content/eus/rhel8/8.6/ppc64le/sap/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/supplementary/debug',
        'content/eus/rhel8/8.6/ppc64le/supplementary/os',
        'content/eus/rhel8/8.6/ppc64le/supplementary/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/appstream/debug',
        'content/eus/rhel8/8.6/s390x/appstream/os',
        'content/eus/rhel8/8.6/s390x/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/baseos/debug',
        'content/eus/rhel8/8.6/s390x/baseos/os',
        'content/eus/rhel8/8.6/s390x/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/codeready-builder/debug',
        'content/eus/rhel8/8.6/s390x/codeready-builder/os',
        'content/eus/rhel8/8.6/s390x/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/highavailability/debug',
        'content/eus/rhel8/8.6/s390x/highavailability/os',
        'content/eus/rhel8/8.6/s390x/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/resilientstorage/debug',
        'content/eus/rhel8/8.6/s390x/resilientstorage/os',
        'content/eus/rhel8/8.6/s390x/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/sap/debug',
        'content/eus/rhel8/8.6/s390x/sap/os',
        'content/eus/rhel8/8.6/s390x/sap/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/supplementary/debug',
        'content/eus/rhel8/8.6/s390x/supplementary/os',
        'content/eus/rhel8/8.6/s390x/supplementary/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/appstream/debug',
        'content/eus/rhel8/8.6/x86_64/appstream/os',
        'content/eus/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/baseos/debug',
        'content/eus/rhel8/8.6/x86_64/baseos/os',
        'content/eus/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/codeready-builder/debug',
        'content/eus/rhel8/8.6/x86_64/codeready-builder/os',
        'content/eus/rhel8/8.6/x86_64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/highavailability/debug',
        'content/eus/rhel8/8.6/x86_64/highavailability/os',
        'content/eus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/resilientstorage/debug',
        'content/eus/rhel8/8.6/x86_64/resilientstorage/os',
        'content/eus/rhel8/8.6/x86_64/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/sap-solutions/debug',
        'content/eus/rhel8/8.6/x86_64/sap-solutions/os',
        'content/eus/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/sap/debug',
        'content/eus/rhel8/8.6/x86_64/sap/os',
        'content/eus/rhel8/8.6/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/supplementary/debug',
        'content/eus/rhel8/8.6/x86_64/supplementary/os',
        'content/eus/rhel8/8.6/x86_64/supplementary/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/appstream/debug',
        'content/tus/rhel8/8.6/x86_64/appstream/os',
        'content/tus/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/baseos/debug',
        'content/tus/rhel8/8.6/x86_64/baseos/os',
        'content/tus/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/highavailability/debug',
        'content/tus/rhel8/8.6/x86_64/highavailability/os',
        'content/tus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/rt/os',
        'content/tus/rhel8/8.6/x86_64/rt/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'jss-4.7.3-1.module+el8.3.0+8058+d5cd4219', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jss-javadoc-4.7.3-1.module+el8.3.0+8058+d5cd4219', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ldapjdk-4.22.0-1.module+el8.3.0+6784+6e1e4c62', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ldapjdk-javadoc-4.22.0-1.module+el8.3.0+6784+6e1e4c62', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'pki-base-10.9.4-1.module+el8.3.0+8058+d5cd4219', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'pki-base-java-10.9.4-1.module+el8.3.0+8058+d5cd4219', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'pki-ca-10.9.4-1.module+el8.3.0+8058+d5cd4219', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'pki-kra-10.9.4-1.module+el8.3.0+8058+d5cd4219', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'pki-server-10.9.4-1.module+el8.3.0+8058+d5cd4219', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'pki-symkey-10.9.4-1.module+el8.3.0+8058+d5cd4219', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'pki-tools-10.9.4-1.module+el8.3.0+8058+d5cd4219', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-pki-10.9.4-1.module+el8.3.0+8058+d5cd4219', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'tomcatjss-7.5.0-1.module+el8.3.0+7355+c59bcbd9', 'sp':'6', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE}
      ]
    },
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
        {'reference':'jss-4.7.3-1.module+el8.3.0+8058+d5cd4219', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jss-javadoc-4.7.3-1.module+el8.3.0+8058+d5cd4219', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ldapjdk-4.22.0-1.module+el8.3.0+6784+6e1e4c62', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ldapjdk-javadoc-4.22.0-1.module+el8.3.0+6784+6e1e4c62', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'pki-base-10.9.4-1.module+el8.3.0+8058+d5cd4219', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'pki-base-java-10.9.4-1.module+el8.3.0+8058+d5cd4219', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'pki-ca-10.9.4-1.module+el8.3.0+8058+d5cd4219', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'pki-kra-10.9.4-1.module+el8.3.0+8058+d5cd4219', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'pki-server-10.9.4-1.module+el8.3.0+8058+d5cd4219', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'pki-symkey-10.9.4-1.module+el8.3.0+8058+d5cd4219', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'pki-tools-10.9.4-1.module+el8.3.0+8058+d5cd4219', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-pki-10.9.4-1.module+el8.3.0+8058+d5cd4219', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'tomcatjss-7.5.0-1.module+el8.3.0+7355+c59bcbd9', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

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
      var enterprise_linux_flag = rhel_repo_urls_has_content_dist_rhel(repo_urls:repo_relative_urls);
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
        if (!empty_or_null(package_array['sp']) && !enterprise_linux_flag) sp = package_array['sp'];
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module pki-core:10.6 / pki-deps:10.6');

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache-commons-collections / apache-commons-lang / apache-commons-net / etc');
}
