#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2531-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(145384);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/02");

  script_cve_id("CVE-2020-28473");

  script_name(english:"Debian DLA-2531-1 : python-bottle security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The package src:python-bottle before 0.12.19 are vulnerable to Web
Cache Poisoning by using a vector called parameter cloaking.

When the attacker can separate query parameters using a semicolon (;),
they can cause a difference in the interpretation of the request
between the proxy (running with default configuration) and the server.
This can result in malicious requests being cached as completely safe
ones, as the proxy would usually not see the semicolon as a separator,
and therefore would not include it in a cache key of an unkeyed
parameter.

For Debian 9 stretch, this problem has been fixed in version
0.12.13-1+deb9u1.

We recommend that you upgrade your python-bottle packages.

For the detailed security status of python-bottle please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/python-bottle

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/01/msg00019.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/python-bottle"
  );
  # https://security-tracker.debian.org/tracker/source-package/python-bottle
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f9e761d2"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-bottle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-bottle-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-bottle");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"python-bottle", reference:"0.12.13-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python-bottle-doc", reference:"0.12.13-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python3-bottle", reference:"0.12.13-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
