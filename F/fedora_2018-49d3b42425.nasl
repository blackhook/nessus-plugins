#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-49d3b42425.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120394);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2018-8011");
  script_xref(name:"FEDORA", value:"2018-49d3b42425");

  script_name(english:"Fedora 28 : httpd (2018-49d3b42425)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update includes the latest upstream release, 

**httpd 2.4.34**, with multiple bug fixes and enhancements. See
http://www.apache.org/dist/httpd/CHANGES_2.4.34 for more information
on the changes in this version.

A security vulnerability is addressed in this update :

  - `mod_md`: DoS via Coredumps on specially crafted
    requests (CVE-2018-8011) The following changes are also
    included in this update :

  - The post-transaction scriptlet to restart
    `httpd.service` no longer blocks waiting for the restart
    to complete.

  - `mod_ssl` now supports loading private keys (and
    associated certificates) from a PKCS#11 provider. Use a
    `pkcs11:` URI in the `SSLCertificateKeyFile` (and
    optionally `SSLCertificateFile`) directive(s).

  - An example Lua-based `server-status.conf` is packaged in
    the docdir 

  - `httpd` now Obsoletes `mod_proxy_uwsgi` (RHBZ#1599113)

  - `mod_systemd` now logs listening ports at startup

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.apache.org/dist/httpd/CHANGES_2.4.34"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-49d3b42425"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected httpd package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:httpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:28");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^28([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 28", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC28", reference:"httpd-2.4.34-3.fc28")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd");
}
