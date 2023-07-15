#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2526-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(145217);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_cve_id("CVE-2020-26298");

  script_name(english:"Debian DLA-2526-1 : ruby-redcarpet security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"In Redcarpet before version 3.5.1, there is an injection vulnerability
which can enable a cross-site scripting attack.

In affected versions, no HTML escaping was being performed when
processing quotes. This applies even when the `:escape_html` option
was being used.

For Debian 9 stretch, this problem has been fixed in version
3.3.4-2+deb9u1.

We recommend that you upgrade your ruby-redcarpet packages.

For the detailed security status of ruby-redcarpet please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/ruby-redcarpet

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/01/msg00014.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/ruby-redcarpet"
  );
  # https://security-tracker.debian.org/tracker/source-package/ruby-redcarpet
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?426d7458"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade the affected ruby-redcarpet package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26298");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-redcarpet");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/20");
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
if (deb_check(release:"9.0", prefix:"ruby-redcarpet", reference:"3.3.4-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
