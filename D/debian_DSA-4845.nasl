#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4845. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(146122);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/05");

  script_cve_id("CVE-2020-36221", "CVE-2020-36222", "CVE-2020-36223", "CVE-2020-36224", "CVE-2020-36225", "CVE-2020-36226", "CVE-2020-36227", "CVE-2020-36228", "CVE-2020-36229", "CVE-2020-36230");
  script_xref(name:"DSA", value:"4845");
  script_xref(name:"IAVB", value:"2021-B-0014");

  script_name(english:"Debian DSA-4845-1 : openldap - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were discovered in OpenLDAP, a free
implementation of the Lightweight Directory Access Protocol. An
unauthenticated remote attacker can take advantage of these flaws to
cause a denial of service (slapd daemon crash, infinite loops) via
specially crafted packets."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/openldap"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/openldap"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2021/dsa-4845"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the openldap packages.

For the stable distribution (buster), these problems have been fixed
in version 2.4.47+dfsg-3+deb10u5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openldap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/04");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (deb_check(release:"10.0", prefix:"ldap-utils", reference:"2.4.47+dfsg-3+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"libldap-2.4-2", reference:"2.4.47+dfsg-3+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"libldap-common", reference:"2.4.47+dfsg-3+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"libldap2-dev", reference:"2.4.47+dfsg-3+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"slapd", reference:"2.4.47+dfsg-3+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"slapd-contrib", reference:"2.4.47+dfsg-3+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"slapd-smbk5pwd", reference:"2.4.47+dfsg-3+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"slapi-dev", reference:"2.4.47+dfsg-3+deb10u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
