#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2676-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(150303);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/14");

  script_cve_id("CVE-2021-33203", "CVE-2021-33571");

  script_name(english:"Debian DLA-2676-1 : python-django security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Two issues were discovered in Django, the Python-based web development
framework :

  - CVE-2021-33203: Potential directory traversal via
    admindocs

    Staff members could use the admindocs TemplateDetailView
    view to check the existence of arbitrary files.
    Additionally, if (and only if) the default admindocs
    templates have been customized by the developers to also
    expose the file contents, then not only the existence
    but also the file contents would have been exposed.

    As a mitigation, path sanitation is now applied and only
    files within the template root directories can be
    loaded.

    This issue has low severity, according to the Django
    security policy.

    Thanks to Rasmus Lerchedahl Petersen and Rasmus Wriedt
    Larsen from the CodeQL Python team for the report.

  - CVE-2021-33571: Possible indeterminate SSRF, RFI, and
    LFI attacks since validators accepted leading zeros in
    IPv4 addresses

    URLValidator, validate_ipv4_address(), and
    validate_ipv46_address() didn't prohibit leading zeros
    in octal literals. If you used such values you could
    suffer from indeterminate SSRF, RFI, and LFI attacks.

    validate_ipv4_address() and validate_ipv46_address()
    validators were not affected on Python 3.9.5+.

    This issue has medium severity, according to the Django
    security policy.

For Debian 9 'Stretch', this problem has been fixed in version
1:1.10.7-2+deb9u14.

We recommend that you upgrade your python-django packages.

For the detailed security status of python-django please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/python-django

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/06/msg00004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/python-django"
  );
  # https://security-tracker.debian.org/tracker/source-package/python-django
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?22eb32f6"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33571");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-django-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-django-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-django");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"python-django", reference:"1:1.10.7-2+deb9u14")) flag++;
if (deb_check(release:"9.0", prefix:"python-django-common", reference:"1:1.10.7-2+deb9u14")) flag++;
if (deb_check(release:"9.0", prefix:"python-django-doc", reference:"1:1.10.7-2+deb9u14")) flag++;
if (deb_check(release:"9.0", prefix:"python3-django", reference:"1:1.10.7-2+deb9u14")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
