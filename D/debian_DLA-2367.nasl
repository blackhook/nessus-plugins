#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2367-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(140298);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/23");

  script_cve_id("CVE-2020-24660");

  script_name(english:"Debian DLA-2367-1 : lemonldap-ng security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"lemonldap-ng community fixed a vulnerability in the Nginx default
configuration files (CVE-2020-24660). Debian package does not install
any default site, but documentation provided insecure examples in
Nginx configuration before this version. If you use lemonldap-ng
handler with Nginx, you should verify your configuration files.

For Debian 9 stretch, this problem has been fixed in version
1.9.7-3+deb9u4.

We recommend that you upgrade your lemonldap-ng packages.

For the detailed security status of lemonldap-ng please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/lemonldap-ng

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/09/msg00006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/lemonldap-ng"
  );
  # https://security-tracker.debian.org/tracker/source-package/lemonldap-ng
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f8cb51e"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lemonldap-ng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lemonldap-ng-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lemonldap-ng-fastcgi-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lemonldap-ng-fr-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lemonldap-ng-handler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblemonldap-ng-common-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblemonldap-ng-conf-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblemonldap-ng-handler-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblemonldap-ng-manager-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblemonldap-ng-portal-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"9.0", prefix:"lemonldap-ng", reference:"1.9.7-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"lemonldap-ng-doc", reference:"1.9.7-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"lemonldap-ng-fastcgi-server", reference:"1.9.7-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"lemonldap-ng-fr-doc", reference:"1.9.7-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"lemonldap-ng-handler", reference:"1.9.7-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"liblemonldap-ng-common-perl", reference:"1.9.7-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"liblemonldap-ng-conf-perl", reference:"1.9.7-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"liblemonldap-ng-handler-perl", reference:"1.9.7-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"liblemonldap-ng-manager-perl", reference:"1.9.7-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"liblemonldap-ng-portal-perl", reference:"1.9.7-3+deb9u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
