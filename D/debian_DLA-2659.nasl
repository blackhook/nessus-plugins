#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2659-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149485);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/19");

  script_cve_id("CVE-2018-10196", "CVE-2020-18032");

  script_name(english:"Debian DLA-2659-1 : graphviz security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"CVE-2018-10196

NULL pointer dereference vulnerability in the rebuild_vlists function
in lib/dotgen/conc.c in the dotgen library allows remote attackers to
cause a denial of service (application crash) via a crafted file.

CVE-2020-18032

A buffer overflow was discovered in Graphviz, which could potentially
result in the execution of arbitrary code when processing a malformed
file.

For Debian 9 stretch, these problems have been fixed in version
2.38.0-17+deb9u1.

We recommend that you upgrade your graphviz packages.

For the detailed security status of graphviz please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/graphviz

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/05/msg00014.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/graphviz"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/graphviz"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-18032");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphviz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphviz-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphviz-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcdt5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcgraph6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphviz-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgv-guile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgv-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgv-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgv-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgv-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgv-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgvc6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgvc6-plugins-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgvpr2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpathplan4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxdot4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/14");
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
if (deb_check(release:"9.0", prefix:"graphviz", reference:"2.38.0-17+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"graphviz-dev", reference:"2.38.0-17+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"graphviz-doc", reference:"2.38.0-17+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcdt5", reference:"2.38.0-17+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcgraph6", reference:"2.38.0-17+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgraphviz-dev", reference:"2.38.0-17+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgv-guile", reference:"2.38.0-17+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgv-lua", reference:"2.38.0-17+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgv-perl", reference:"2.38.0-17+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgv-python", reference:"2.38.0-17+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgv-ruby", reference:"2.38.0-17+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgv-tcl", reference:"2.38.0-17+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgvc6", reference:"2.38.0-17+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgvc6-plugins-gtk", reference:"2.38.0-17+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgvpr2", reference:"2.38.0-17+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpathplan4", reference:"2.38.0-17+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libxdot4", reference:"2.38.0-17+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
