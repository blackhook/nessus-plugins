#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4851. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(146514);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/26");

  script_cve_id("CVE-2020-17525");
  script_xref(name:"DSA", value:"4851");
  script_xref(name:"IAVA", value:"2021-A-0094");

  script_name(english:"Debian DSA-4851-1 : subversion - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Thomas Akesson discovered a remotely triggerable vulnerability in the
mod_authz_svn module in Subversion, a version control system. When
using in-repository authz rules with the
AuthzSVNReposRelativeAccessFile option an unauthenticated remote
client can take advantage of this flaw to cause a denial of service by
sending a request for a non-existing repository URL."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=982464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/subversion"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/subversion"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2021/dsa-4851"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the subversion packages.

For the stable distribution (buster), this problem has been fixed in
version 1.10.4-1+deb10u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (deb_check(release:"10.0", prefix:"libapache2-mod-svn", reference:"1.10.4-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libsvn-dev", reference:"1.10.4-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libsvn-doc", reference:"1.10.4-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libsvn-java", reference:"1.10.4-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libsvn-perl", reference:"1.10.4-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libsvn1", reference:"1.10.4-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"python-subversion", reference:"1.10.4-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"ruby-svn", reference:"1.10.4-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"subversion", reference:"1.10.4-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"subversion-tools", reference:"1.10.4-1+deb10u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
