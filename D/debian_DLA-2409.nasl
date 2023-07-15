#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2409-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(141794);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/14");

  script_cve_id("CVE-2020-15180");

  script_name(english:"Debian DLA-2409-1 : mariadb-10.1 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A security issue was discovered in the MariaDB database server.

For Debian 9 stretch, this problem has been fixed in version
10.1.47-0+deb9u1.

We recommend that you upgrade your mariadb-10.1 packages.

For the detailed security status of mariadb-10.1 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/mariadb-10.1

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/10/msg00021.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/mariadb-10.1"
  );
  # https://security-tracker.debian.org/tracker/source-package/mariadb-10.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?708f0173"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15180");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmariadbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmariadbclient-dev-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmariadbclient18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmariadbd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmariadbd18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-client-10.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-client-core-10.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-plugin-connect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-plugin-cracklib-password-check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-plugin-gssapi-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-plugin-gssapi-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-plugin-mroonga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-plugin-oqgraph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-plugin-spider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-plugin-tokudb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-server-10.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-server-core-10.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-test-data");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libmariadbclient-dev", reference:"10.1.47-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libmariadbclient-dev-compat", reference:"10.1.47-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libmariadbclient18", reference:"10.1.47-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libmariadbd-dev", reference:"10.1.47-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libmariadbd18", reference:"10.1.47-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-client", reference:"10.1.47-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-client-10.1", reference:"10.1.47-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-client-core-10.1", reference:"10.1.47-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-common", reference:"10.1.47-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-plugin-connect", reference:"10.1.47-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-plugin-cracklib-password-check", reference:"10.1.47-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-plugin-gssapi-client", reference:"10.1.47-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-plugin-gssapi-server", reference:"10.1.47-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-plugin-mroonga", reference:"10.1.47-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-plugin-oqgraph", reference:"10.1.47-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-plugin-spider", reference:"10.1.47-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-plugin-tokudb", reference:"10.1.47-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-server", reference:"10.1.47-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-server-10.1", reference:"10.1.47-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-server-core-10.1", reference:"10.1.47-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-test", reference:"10.1.47-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-test-data", reference:"10.1.47-0+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
