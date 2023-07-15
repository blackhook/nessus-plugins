#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2331-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139629);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/04");

  script_cve_id("CVE-2020-14350");
  script_xref(name:"IAVB", value:"2020-B-0047-S");

  script_name(english:"Debian DLA-2331-1 : posgresql-9.6 security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Andres Freund found an issue in the PostgreSQL database system where
an uncontrolled search path could allow users to run arbitrary SQL
functions with elevated priviledges when a superuser runs certain
`CREATE EXTENSION' statements.

For Debian 9 stretch, this problem has been fixed in version
9.6.19-0+deb9u1.

We recommend that you upgrade your posgresql-9.6 packages.

For the detailed security status of posgresql-9.6 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/posgresql-9.6

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00028.html");
  # https://security-tracker.debian.org/tracker/source-package/posgresql-9.6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a3a3d42c");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade the affected posgresql-9.6 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14350");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:posgresql-9.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (deb_check(release:"9.0", prefix:"posgresql-9.6", reference:"9.6.19-0+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
