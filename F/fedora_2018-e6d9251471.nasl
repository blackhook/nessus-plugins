#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-e6d9251471.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109745);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-15710", "CVE-2017-15715", "CVE-2018-1283", "CVE-2018-1301", "CVE-2018-1303", "CVE-2018-1312");
  script_xref(name:"FEDORA", value:"2018-e6d9251471");

  script_name(english:"Fedora 26 : httpd (2018-e6d9251471)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update :

  - fixes the **mod_md** default store directory

  - fixes a startup failure in certain **mod_ssl** vhost
    configurations

----

This update includes the latest upstream release of the Apache HTTP
Server, version 2.4.33. A number of security vulnerabilities are fixed
in this release :

  - *Low*: Possible out of bound read in mod_cache_socache
    (CVE-2018-1303)

  - *Low*: Possible out of bound access after failure in
    reading the HTTP request (CVE-2018-1301)

  - *Low*: Weak Digest auth nonce generation in
    mod_auth_digest (CVE-2018-1312)

  - *Low*: <FilesMatch> bypass with a trailing newline in
    the file name (CVE-2017-15715)

  - *Low*: Out of bound write in mod_authnz_ldap when using
    too small Accept-Language values (CVE-2017-15710)

  - *Moderate*: Tampering of mod_session data for CGI
    applications (CVE-2018-1283)

For more information about changes in this release, see:
https://www.apache.org/dist/httpd/CHANGES_2.4.33

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-e6d9251471"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected httpd package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:httpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:26");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^26([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 26", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC26", reference:"httpd-2.4.33-4.fc26")) flag++;


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
