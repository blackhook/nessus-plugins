##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:0514. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(133749);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id(
    "CVE-2019-18197",
    "CVE-2019-19880",
    "CVE-2019-19923",
    "CVE-2019-19925",
    "CVE-2019-19926",
    "CVE-2020-6381",
    "CVE-2020-6382",
    "CVE-2020-6385",
    "CVE-2020-6387",
    "CVE-2020-6388",
    "CVE-2020-6389",
    "CVE-2020-6390",
    "CVE-2020-6391",
    "CVE-2020-6392",
    "CVE-2020-6393",
    "CVE-2020-6394",
    "CVE-2020-6395",
    "CVE-2020-6396",
    "CVE-2020-6397",
    "CVE-2020-6398",
    "CVE-2020-6399",
    "CVE-2020-6400",
    "CVE-2020-6401",
    "CVE-2020-6402",
    "CVE-2020-6403",
    "CVE-2020-6404",
    "CVE-2020-6405",
    "CVE-2020-6406",
    "CVE-2020-6408",
    "CVE-2020-6409",
    "CVE-2020-6410",
    "CVE-2020-6411",
    "CVE-2020-6412",
    "CVE-2020-6413",
    "CVE-2020-6414",
    "CVE-2020-6415",
    "CVE-2020-6416",
    "CVE-2020-6417"
  );
  script_xref(name:"RHSA", value:"2020:0514");
  script_xref(name:"IAVA", value:"2020-A-0051-S");

  script_name(english:"RHEL 6 : chromium-browser (RHSA-2020:0514)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has a package installed that is affected by multiple vulnerabilities as
referenced in the RHSA-2020:0514 advisory.

  - libxslt: use after free in xsltCopyText in transform.c could lead to information disclosure
    (CVE-2019-18197)

  - CVE-2019-19926 sqlite: error mishandling because of incomplete fix of (CVE-2019-19880)

  - sqlite: mishandling of certain uses of SELECT DISTINCT involving a LEFT JOIN in flattenSubquery in
    select.c leads to a NULL pointer dereference (CVE-2019-19923)

  - sqlite: zipfileUpdate in ext/misc/zipfile.c mishandles a NULL pathname during an update of a ZIP archive
    (CVE-2019-19925)

  - sqlite: error mishandling because of incomplete fix of CVE-2019-19880 (CVE-2019-19926)

  - chromium-browser: Integer overflow in JavaScript (CVE-2020-6381)

  - chromium-browser: Type Confusion in JavaScript (CVE-2020-6382)

  - chromium-browser: Insufficient policy enforcement in storage (CVE-2020-6385)

  - chromium-browser: Out of bounds write in WebRTC (CVE-2020-6387, CVE-2020-6389)

  - chromium-browser: Out of bounds memory access in WebAudio (CVE-2020-6388)

  - chromium-browser: Out of bounds memory access in streams (CVE-2020-6390)

  - chromium-browser: Insufficient validation of untrusted input in Blink (CVE-2020-6391)

  - chromium-browser: Insufficient policy enforcement in extensions (CVE-2020-6392)

  - chromium-browser: Insufficient policy enforcement in Blink (CVE-2020-6393, CVE-2020-6394)

  - chromium-browser: Out of bounds read in JavaScript (CVE-2020-6395)

  - chromium-browser: Inappropriate implementation in Skia (CVE-2020-6396)

  - chromium-browser: Incorrect security UI in sharing (CVE-2020-6397)

  - chromium-browser: Uninitialized use in PDFium (CVE-2020-6398)

  - chromium-browser: Insufficient policy enforcement in AppCache (CVE-2020-6399)

  - chromium-browser: Inappropriate implementation in CORS (CVE-2020-6400)

  - chromium-browser: Insufficient validation of untrusted input in Omnibox (CVE-2020-6401, CVE-2020-6411,
    CVE-2020-6412)

  - chromium-browser: Insufficient policy enforcement in downloads (CVE-2020-6402)

  - chromium-browser: Incorrect security UI in Omnibox (CVE-2020-6403)

  - chromium-browser: Inappropriate implementation in Blink (CVE-2020-6404, CVE-2020-6413)

  - sqlite: Out-of-bounds read in SELECT with ON/USING clause (CVE-2020-6405)

  - chromium-browser: Use after free in audio (CVE-2020-6406)

  - chromium-browser: Insufficient policy enforcement in CORS (CVE-2020-6408)

  - chromium-browser: Inappropriate implementation in Omnibox (CVE-2020-6409)

  - chromium-browser: Insufficient policy enforcement in navigation (CVE-2020-6410)

  - chromium-browser: Insufficient policy enforcement in Safe Browsing (CVE-2020-6414)

  - chromium-browser: Inappropriate implementation in JavaScript (CVE-2020-6415)

  - chromium-browser: Insufficient data validation in streams (CVE-2020-6416)

  - chromium-browser: Inappropriate implementation in installer (CVE-2020-6417)

  - chromium-browser: Inappropriate implementation in AppCache (CVE-2020-6499)

  - chromium-browser: Inappropriate implementation in interstitials (CVE-2020-6500)

  - chromium-browser: Insufficient policy enforcement in CSP (CVE-2020-6501)

  - chromium-browser: Incorrect security UI in permissions (CVE-2020-6502)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-18197");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19880");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19923");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19925");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19926");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6381");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6382");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6385");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6387");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6388");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6389");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6390");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6391");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6392");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6393");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6394");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6395");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6396");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6397");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6398");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6399");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6400");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6401");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6402");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6403");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6404");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6405");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6406");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6408");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6409");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6410");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6411");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6412");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6413");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6414");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6415");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6416");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6417");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6499");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6500");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6501");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6502");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:0514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1770768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1787032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1788846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1788866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1789364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801160");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801161");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801162");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801163");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801164");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801165");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801172");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801173");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801174");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801175");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801176");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801177");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801178");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801179");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801181");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801182");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801184");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801185");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801186");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801188");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801190");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801192");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1844539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1844542");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1844546");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1844549");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromium-browser package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6416");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 125, 416, 476);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_els:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:6.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:chromium-browser");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '6')) audit(AUDIT_OS_NOT, 'Red Hat 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/6/6Client/i386/debug',
      'content/dist/rhel/client/6/6Client/i386/optional/debug',
      'content/dist/rhel/client/6/6Client/i386/optional/os',
      'content/dist/rhel/client/6/6Client/i386/optional/source/SRPMS',
      'content/dist/rhel/client/6/6Client/i386/oracle-java-rm/os',
      'content/dist/rhel/client/6/6Client/i386/oracle-java-rm/source/SRPMS',
      'content/dist/rhel/client/6/6Client/i386/os',
      'content/dist/rhel/client/6/6Client/i386/source/SRPMS',
      'content/dist/rhel/client/6/6Client/i386/supplementary/debug',
      'content/dist/rhel/client/6/6Client/i386/supplementary/os',
      'content/dist/rhel/client/6/6Client/i386/supplementary/source/SRPMS',
      'content/dist/rhel/client/6/6Client/x86_64/debug',
      'content/dist/rhel/client/6/6Client/x86_64/optional/debug',
      'content/dist/rhel/client/6/6Client/x86_64/optional/os',
      'content/dist/rhel/client/6/6Client/x86_64/optional/source/SRPMS',
      'content/dist/rhel/client/6/6Client/x86_64/oracle-java-rm/os',
      'content/dist/rhel/client/6/6Client/x86_64/oracle-java-rm/source/SRPMS',
      'content/dist/rhel/client/6/6Client/x86_64/os',
      'content/dist/rhel/client/6/6Client/x86_64/source/SRPMS',
      'content/dist/rhel/client/6/6Client/x86_64/supplementary/debug',
      'content/dist/rhel/client/6/6Client/x86_64/supplementary/os',
      'content/dist/rhel/client/6/6Client/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/hpn/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/hpn/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/hpn/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/optional/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/optional/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/optional/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/oracle-java-rm/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/oracle-java-rm/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/scalablefilesystem/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/scalablefilesystem/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/scalablefilesystem/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/supplementary/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/supplementary/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/debug',
      'content/dist/rhel/server/6/6Server/i386/highavailability/debug',
      'content/dist/rhel/server/6/6Server/i386/highavailability/os',
      'content/dist/rhel/server/6/6Server/i386/highavailability/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/loadbalancer/debug',
      'content/dist/rhel/server/6/6Server/i386/loadbalancer/os',
      'content/dist/rhel/server/6/6Server/i386/loadbalancer/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/optional/debug',
      'content/dist/rhel/server/6/6Server/i386/optional/os',
      'content/dist/rhel/server/6/6Server/i386/optional/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/oracle-java-rm/os',
      'content/dist/rhel/server/6/6Server/i386/oracle-java-rm/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/os',
      'content/dist/rhel/server/6/6Server/i386/resilientstorage/debug',
      'content/dist/rhel/server/6/6Server/i386/resilientstorage/os',
      'content/dist/rhel/server/6/6Server/i386/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/supplementary/debug',
      'content/dist/rhel/server/6/6Server/i386/supplementary/os',
      'content/dist/rhel/server/6/6Server/i386/supplementary/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/debug',
      'content/dist/rhel/server/6/6Server/x86_64/highavailability/debug',
      'content/dist/rhel/server/6/6Server/x86_64/highavailability/os',
      'content/dist/rhel/server/6/6Server/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/hpn/debug',
      'content/dist/rhel/server/6/6Server/x86_64/hpn/os',
      'content/dist/rhel/server/6/6Server/x86_64/hpn/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/loadbalancer/debug',
      'content/dist/rhel/server/6/6Server/x86_64/loadbalancer/os',
      'content/dist/rhel/server/6/6Server/x86_64/loadbalancer/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/optional/debug',
      'content/dist/rhel/server/6/6Server/x86_64/optional/os',
      'content/dist/rhel/server/6/6Server/x86_64/optional/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/oracle-java-rm/os',
      'content/dist/rhel/server/6/6Server/x86_64/oracle-java-rm/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/os',
      'content/dist/rhel/server/6/6Server/x86_64/resilientstorage/debug',
      'content/dist/rhel/server/6/6Server/x86_64/resilientstorage/os',
      'content/dist/rhel/server/6/6Server/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/sap-hana/debug',
      'content/dist/rhel/server/6/6Server/x86_64/sap-hana/os',
      'content/dist/rhel/server/6/6Server/x86_64/sap-hana/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/sap/debug',
      'content/dist/rhel/server/6/6Server/x86_64/sap/os',
      'content/dist/rhel/server/6/6Server/x86_64/sap/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/scalablefilesystem/debug',
      'content/dist/rhel/server/6/6Server/x86_64/scalablefilesystem/os',
      'content/dist/rhel/server/6/6Server/x86_64/scalablefilesystem/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/supplementary/debug',
      'content/dist/rhel/server/6/6Server/x86_64/supplementary/os',
      'content/dist/rhel/server/6/6Server/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/i386/debug',
      'content/dist/rhel/workstation/6/6Workstation/i386/optional/debug',
      'content/dist/rhel/workstation/6/6Workstation/i386/optional/os',
      'content/dist/rhel/workstation/6/6Workstation/i386/optional/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/i386/oracle-java-rm/os',
      'content/dist/rhel/workstation/6/6Workstation/i386/oracle-java-rm/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/i386/os',
      'content/dist/rhel/workstation/6/6Workstation/i386/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/i386/supplementary/debug',
      'content/dist/rhel/workstation/6/6Workstation/i386/supplementary/os',
      'content/dist/rhel/workstation/6/6Workstation/i386/supplementary/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/optional/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/optional/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/optional/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/oracle-java-rm/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/oracle-java-rm/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/scalablefilesystem/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/scalablefilesystem/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/scalablefilesystem/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/supplementary/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/supplementary/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/supplementary/source/SRPMS',
      'content/els/rhel/server/6/6Server/i386/debug',
      'content/els/rhel/server/6/6Server/i386/optional/debug',
      'content/els/rhel/server/6/6Server/i386/optional/os',
      'content/els/rhel/server/6/6Server/i386/optional/source/SRPMS',
      'content/els/rhel/server/6/6Server/i386/os',
      'content/els/rhel/server/6/6Server/i386/source/SRPMS',
      'content/els/rhel/server/6/6Server/x86_64/debug',
      'content/els/rhel/server/6/6Server/x86_64/optional/debug',
      'content/els/rhel/server/6/6Server/x86_64/optional/os',
      'content/els/rhel/server/6/6Server/x86_64/optional/source/SRPMS',
      'content/els/rhel/server/6/6Server/x86_64/os',
      'content/els/rhel/server/6/6Server/x86_64/sap-hana/debug',
      'content/els/rhel/server/6/6Server/x86_64/sap-hana/os',
      'content/els/rhel/server/6/6Server/x86_64/sap-hana/source/SRPMS',
      'content/els/rhel/server/6/6Server/x86_64/sap/debug',
      'content/els/rhel/server/6/6Server/x86_64/sap/os',
      'content/els/rhel/server/6/6Server/x86_64/sap/source/SRPMS',
      'content/els/rhel/server/6/6Server/x86_64/source/SRPMS',
      'content/fastrack/rhel/client/6/i386/debug',
      'content/fastrack/rhel/client/6/i386/optional/debug',
      'content/fastrack/rhel/client/6/i386/optional/os',
      'content/fastrack/rhel/client/6/i386/optional/source/SRPMS',
      'content/fastrack/rhel/client/6/i386/os',
      'content/fastrack/rhel/client/6/i386/source/SRPMS',
      'content/fastrack/rhel/client/6/x86_64/debug',
      'content/fastrack/rhel/client/6/x86_64/optional/debug',
      'content/fastrack/rhel/client/6/x86_64/optional/os',
      'content/fastrack/rhel/client/6/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/client/6/x86_64/os',
      'content/fastrack/rhel/client/6/x86_64/source/SRPMS',
      'content/fastrack/rhel/computenode/6/x86_64/debug',
      'content/fastrack/rhel/computenode/6/x86_64/hpn/debug',
      'content/fastrack/rhel/computenode/6/x86_64/hpn/os',
      'content/fastrack/rhel/computenode/6/x86_64/hpn/source/SRPMS',
      'content/fastrack/rhel/computenode/6/x86_64/optional/debug',
      'content/fastrack/rhel/computenode/6/x86_64/optional/os',
      'content/fastrack/rhel/computenode/6/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/computenode/6/x86_64/os',
      'content/fastrack/rhel/computenode/6/x86_64/scalablefilesystem/debug',
      'content/fastrack/rhel/computenode/6/x86_64/scalablefilesystem/os',
      'content/fastrack/rhel/computenode/6/x86_64/scalablefilesystem/source/SRPMS',
      'content/fastrack/rhel/computenode/6/x86_64/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/debug',
      'content/fastrack/rhel/server/6/i386/highavailability/debug',
      'content/fastrack/rhel/server/6/i386/highavailability/os',
      'content/fastrack/rhel/server/6/i386/highavailability/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/loadbalancer/debug',
      'content/fastrack/rhel/server/6/i386/loadbalancer/os',
      'content/fastrack/rhel/server/6/i386/loadbalancer/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/optional/debug',
      'content/fastrack/rhel/server/6/i386/optional/os',
      'content/fastrack/rhel/server/6/i386/optional/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/os',
      'content/fastrack/rhel/server/6/i386/resilientstorage/debug',
      'content/fastrack/rhel/server/6/i386/resilientstorage/os',
      'content/fastrack/rhel/server/6/i386/resilientstorage/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/debug',
      'content/fastrack/rhel/server/6/x86_64/highavailability/debug',
      'content/fastrack/rhel/server/6/x86_64/highavailability/os',
      'content/fastrack/rhel/server/6/x86_64/highavailability/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/hpn/debug',
      'content/fastrack/rhel/server/6/x86_64/hpn/os',
      'content/fastrack/rhel/server/6/x86_64/hpn/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/loadbalancer/debug',
      'content/fastrack/rhel/server/6/x86_64/loadbalancer/os',
      'content/fastrack/rhel/server/6/x86_64/loadbalancer/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/optional/debug',
      'content/fastrack/rhel/server/6/x86_64/optional/os',
      'content/fastrack/rhel/server/6/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/os',
      'content/fastrack/rhel/server/6/x86_64/resilientstorage/debug',
      'content/fastrack/rhel/server/6/x86_64/resilientstorage/os',
      'content/fastrack/rhel/server/6/x86_64/resilientstorage/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/scalablefilesystem/debug',
      'content/fastrack/rhel/server/6/x86_64/scalablefilesystem/os',
      'content/fastrack/rhel/server/6/x86_64/scalablefilesystem/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/source/SRPMS',
      'content/fastrack/rhel/workstation/6/i386/debug',
      'content/fastrack/rhel/workstation/6/i386/optional/debug',
      'content/fastrack/rhel/workstation/6/i386/optional/os',
      'content/fastrack/rhel/workstation/6/i386/optional/source/SRPMS',
      'content/fastrack/rhel/workstation/6/i386/os',
      'content/fastrack/rhel/workstation/6/i386/source/SRPMS',
      'content/fastrack/rhel/workstation/6/x86_64/debug',
      'content/fastrack/rhel/workstation/6/x86_64/optional/debug',
      'content/fastrack/rhel/workstation/6/x86_64/optional/os',
      'content/fastrack/rhel/workstation/6/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/workstation/6/x86_64/os',
      'content/fastrack/rhel/workstation/6/x86_64/scalablefilesystem/debug',
      'content/fastrack/rhel/workstation/6/x86_64/scalablefilesystem/os',
      'content/fastrack/rhel/workstation/6/x86_64/scalablefilesystem/source/SRPMS',
      'content/fastrack/rhel/workstation/6/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'chromium-browser-80.0.3987.87-1.el6_10', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
      {'reference':'chromium-browser-80.0.3987.87-1.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  var enterprise_linux_flag = rhel_repo_urls_has_content_dist_rhel(repo_urls:repo_relative_urls);
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp']) && !enterprise_linux_flag) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromium-browser');
}
