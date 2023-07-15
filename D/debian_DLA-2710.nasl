#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2710. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152075);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2017-4965",
    "CVE-2017-4966",
    "CVE-2017-4967",
    "CVE-2019-11281",
    "CVE-2019-11287",
    "CVE-2021-22116"
  );
  script_xref(name:"IAVB", value:"2017-B-0057-S");
  script_xref(name:"IAVB", value:"2021-B-0029-S");

  script_name(english:"Debian DLA-2710-1 : rabbitmq-server - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-2710 advisory.

  - An issue was discovered in these Pivotal RabbitMQ versions: all 3.4.x versions, all 3.5.x versions, and
    3.6.x versions prior to 3.6.9; and these RabbitMQ for PCF versions: all 1.5.x versions, 1.6.x versions
    prior to 1.6.18, and 1.7.x versions prior to 1.7.15. Several forms in the RabbitMQ management UI are
    vulnerable to XSS attacks. (CVE-2017-4965, CVE-2017-4967)

  - An issue was discovered in these Pivotal RabbitMQ versions: all 3.4.x versions, all 3.5.x versions, and
    3.6.x versions prior to 3.6.9; and these RabbitMQ for PCF versions: all 1.5.x versions, 1.6.x versions
    prior to 1.6.18, and 1.7.x versions prior to 1.7.15. RabbitMQ management UI stores signed-in user
    credentials in a browser's local storage without expiration, making it possible to retrieve them using a
    chained attack. (CVE-2017-4966)

  - Pivotal RabbitMQ, versions prior to v3.7.18, and RabbitMQ for PCF, versions 1.15.x prior to 1.15.13,
    versions 1.16.x prior to 1.16.6, and versions 1.17.x prior to 1.17.3, contain two components, the virtual
    host limits page, and the federation management UI, which do not properly sanitize user input. A remote
    authenticated malicious user with administrative access could craft a cross site scripting attack that
    would gain access to virtual hosts and policy management information. (CVE-2019-11281)

  - Pivotal RabbitMQ, versions 3.7.x prior to 3.7.21 and 3.8.x prior to 3.8.1, and RabbitMQ for Pivotal
    Platform, 1.16.x versions prior to 1.16.7 and 1.17.x versions prior to 1.17.4, contain a web management
    plugin that is vulnerable to a denial of service attack. The X-Reason HTTP Header can be leveraged to
    insert a malicious Erlang format string that will expand and consume the heap, resulting in the server
    crashing. (CVE-2019-11287)

  - RabbitMQ all versions prior to 3.8.16 are prone to a denial of service vulnerability due to improper input
    validation in AMQP 1.0 client connection endpoint. A malicious user can exploit the vulnerability by
    sending malicious AMQP messages to the target RabbitMQ instance having the AMQP 1.0 plugin enabled.
    (CVE-2021-22116)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/rabbitmq-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0a75fd6");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2710");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-4965");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-4966");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-4967");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-11281");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-11287");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-22116");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/rabbitmq-server");
  script_set_attribute(attribute:"solution", value:
"Upgrade the rabbitmq-server packages.

For Debian 9 stretch, these problems have been fixed in version 3.6.6-1+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-4967");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-4966");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rabbitmq-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

pkgs = [
    {'release': '9.0', 'prefix': 'rabbitmq-server', 'reference': '3.6.6-1+deb9u1'}
];

flag = 0;
foreach package_array ( pkgs ) {
  release = NULL;
  prefix = NULL;
  reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rabbitmq-server');
}
