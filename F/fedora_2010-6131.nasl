#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-6131.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(47417);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2009-3555", "CVE-2010-0408", "CVE-2010-0434");
  script_bugtraq_id(36935, 38491, 38494, 38580);
  script_xref(name:"FEDORA", value:"2010-6131");

  script_name(english:"Fedora 11 : httpd-2.2.15-1.fc11.1 (2010-6131)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Apache HTTP Server Project is proud to announce the release of
version 2.2.15 of the Apache HTTP Server ('httpd'). This version is
principally a security and bugfix release. Notably, this release was
updated to reflect the OpenSSL Project's release 0.9.8m of the openssl
library, and addresses CVE-2009-3555 (cve.mitre.org), the TLS
renegotiation prefix injection attack. This release further addresses
the issues CVE-2010-0408 and CVE-2010-0434 within mod_proxy_ajp and
mod_headers respectively. See the upstream changes file for further
information: http://www.apache.org/dist/httpd/CHANGES_2.2.15

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.apache.org/dist/httpd/CHANGES_2.2.15"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=569905"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=570171"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/040652.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b52c1a0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected httpd package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:httpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 Tenable Network Security, Inc.");
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
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^11([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 11.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC11", reference:"httpd-2.2.15-1.fc11.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd");
}
