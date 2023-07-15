#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5399. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(175152);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/05");

  script_cve_id(
    "CVE-2021-23166",
    "CVE-2021-23176",
    "CVE-2021-23178",
    "CVE-2021-23186",
    "CVE-2021-23203",
    "CVE-2021-26263",
    "CVE-2021-26947",
    "CVE-2021-44476",
    "CVE-2021-44775",
    "CVE-2021-45071",
    "CVE-2021-45111"
  );

  script_name(english:"Debian DSA-5399-1 : odoo - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dsa-5399 advisory.

  - A sandboxing issue in Odoo Community 15.0 and earlier and Odoo Enterprise 15.0 and earlier allows
    authenticated administrators to read and write local files on the server. (CVE-2021-23166)

  - Improper access control in reporting engine of l10n_fr_fec module in Odoo Community 15.0 and earlier and
    Odoo Enterprise 15.0 and earlier allows remote authenticated users to extract accounting information via
    crafted RPC packets. (CVE-2021-23176)

  - Improper access control in Odoo Community 15.0 and earlier and Odoo Enterprise 15.0 and earlier allows
    attackers to validate online payments with a tokenized payment method that belongs to another user,
    causing the victim's payment method to be charged instead. (CVE-2021-23178)

  - A sandboxing issue in Odoo Community 15.0 and earlier and Odoo Enterprise 15.0 and earlier allows
    authenticated administrators to access and modify database contents of other tenants, in a multi-tenant
    system. (CVE-2021-23186)

  - Improper access control in reporting engine of Odoo Community 14.0 through 15.0, and Odoo Enterprise 14.0
    through 15.0, allows remote attackers to download PDF reports for arbitrary documents, via crafted
    requests. (CVE-2021-23203)

  - Cross-site scripting (XSS) issue in Discuss app of Odoo Community 14.0 through 15.0, and Odoo Enterprise
    14.0 through 15.0, allows remote attackers to inject arbitrary web script in the browser of a victim, by
    posting crafted contents. (CVE-2021-26263)

  - Cross-site scripting (XSS) issue Odoo Community 15.0 and earlier and Odoo Enterprise 15.0 and earlier,
    allows remote attackers to inject arbitrary web script in the browser of a victim, via a crafted link.
    (CVE-2021-26947)

  - A sandboxing issue in Odoo Community 15.0 and earlier and Odoo Enterprise 15.0 and earlier allows
    authenticated administrators to read local files on the server, including sensitive configuration files.
    (CVE-2021-44476)

  - Cross-site scripting (XSS) issue in Website app of Odoo Community 15.0 and earlier and Odoo Enterprise
    15.0 and earlier, allows remote attackers to inject arbitrary web script in the browser of a victim, by
    posting crafted contents. (CVE-2021-44775)

  - Cross-site scripting (XSS) issue Odoo Community 15.0 and earlier and Odoo Enterprise 15.0 and earlier,
    allows remote attackers to inject arbitrary web script in the browser of a victim, via crafted uploaded
    file names. (CVE-2021-45071)

  - Improper access control in Odoo Community 15.0 and earlier and Odoo Enterprise 15.0 and earlier allows
    remote authenticated users to trigger the creation of demonstration data, including user accounts with
    known credentials. (CVE-2021-45111)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/odoo");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5399");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-23166");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-23176");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-23178");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-23186");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-23203");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-26263");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-26947");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-44476");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-44775");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45071");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45111");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/odoo");
  script_set_attribute(attribute:"solution", value:
"Upgrade the odoo packages.

For the stable distribution (bullseye), these problems have been fixed in version 14.0.0+dfsg.2-7+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-45111");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-23186");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:odoo-14");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'odoo-14', 'reference': '14.0.0+dfsg.2-7+deb11u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'odoo-14');
}
