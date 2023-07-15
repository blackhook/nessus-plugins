#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4776. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(141725);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/21");

  script_cve_id("CVE-2020-15180");
  script_xref(name:"DSA", value:"4776");

  script_name(english:"Debian DSA-4776-1 : mariadb-10.3 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:"A security issue was discovered in the MariaDB database server."
  );
  # https://security-tracker.debian.org/tracker/source-package/mariadb-10.3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb6537b5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/mariadb-10.3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4776"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the mariadb-10.3 packages.

For the stable distribution (buster), this problem has been fixed in
version 1:10.3.25-0+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15180");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-10.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"libmariadb-dev", reference:"1:10.3.25-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmariadb-dev-compat", reference:"1:10.3.25-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmariadb3", reference:"1:10.3.25-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmariadbclient-dev", reference:"1:10.3.25-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmariadbd-dev", reference:"1:10.3.25-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmariadbd19", reference:"1:10.3.25-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"mariadb-backup", reference:"1:10.3.25-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"mariadb-client", reference:"1:10.3.25-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"mariadb-client-10.3", reference:"1:10.3.25-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"mariadb-client-core-10.3", reference:"1:10.3.25-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"mariadb-common", reference:"1:10.3.25-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"mariadb-plugin-connect", reference:"1:10.3.25-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"mariadb-plugin-cracklib-password-check", reference:"1:10.3.25-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"mariadb-plugin-gssapi-client", reference:"1:10.3.25-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"mariadb-plugin-gssapi-server", reference:"1:10.3.25-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"mariadb-plugin-mroonga", reference:"1:10.3.25-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"mariadb-plugin-oqgraph", reference:"1:10.3.25-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"mariadb-plugin-rocksdb", reference:"1:10.3.25-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"mariadb-plugin-spider", reference:"1:10.3.25-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"mariadb-plugin-tokudb", reference:"1:10.3.25-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"mariadb-server", reference:"1:10.3.25-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"mariadb-server-10.3", reference:"1:10.3.25-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"mariadb-server-core-10.3", reference:"1:10.3.25-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"mariadb-test", reference:"1:10.3.25-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"mariadb-test-data", reference:"1:10.3.25-0+deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
