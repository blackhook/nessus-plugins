#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2656-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149423);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/01");

  script_cve_id("CVE-2021-3504");

  script_name(english:"Debian DLA-2656-1 : hivex security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Jemery Galindo discovered an out-of-bounds memory access in Hivex, a
library to parse Windows Registry hive files.

For Debian 9 stretch, this problem has been fixed in version
1.3.13-2+deb9u1.

We recommend that you upgrade your hivex packages.

For the detailed security status of hivex please refer to its security
tracker page at: https://security-tracker.debian.org/tracker/hivex

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/05/msg00011.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/hivex"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/hivex"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3504");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhivex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhivex-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhivex-ocaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhivex-ocaml-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhivex0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhivex0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwin-hivex-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-hivex");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/12");
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
if (deb_check(release:"9.0", prefix:"libhivex-bin", reference:"1.3.13-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libhivex-dev", reference:"1.3.13-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libhivex-ocaml", reference:"1.3.13-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libhivex-ocaml-dev", reference:"1.3.13-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libhivex0", reference:"1.3.13-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libhivex0-dbg", reference:"1.3.13-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwin-hivex-perl", reference:"1.3.13-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python-hivex", reference:"1.3.13-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python3-hivex", reference:"1.3.13-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"ruby-hivex", reference:"1.3.13-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
