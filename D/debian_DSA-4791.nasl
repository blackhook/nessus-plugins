#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4791. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(142920);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/09");

  script_cve_id("CVE-2020-25654");
  script_xref(name:"DSA", value:"4791");

  script_name(english:"Debian DSA-4791-1 : pacemaker - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Ken Gaillot discovered a vulnerability in the Pacemaker cluster
resource manager: If ACLs were configured for users in the
'haclient'group, the ACL restrictions could be bypassed via
unrestricted IPC communication, resulting in cluster-wide arbitrary
code execution with root privileges.

If the 'enable-acl' cluster option isn't enabled, members of
the'haclient' group can modify Pacemaker's Cluster Information Base
without restriction, which already gives them these capabilities, so
there is no additional exposure in such a setup."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=973254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/pacemaker"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/pacemaker"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4791"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the pacemaker packages.

For the stable distribution (buster), this problem has been fixed in
version 2.0.1-5+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pacemaker");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (deb_check(release:"10.0", prefix:"libcib-dev", reference:"2.0.1-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libcib27", reference:"2.0.1-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libcrmcluster-dev", reference:"2.0.1-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libcrmcluster29", reference:"2.0.1-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libcrmcommon-dev", reference:"2.0.1-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libcrmcommon34", reference:"2.0.1-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libcrmservice-dev", reference:"2.0.1-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libcrmservice28", reference:"2.0.1-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"liblrmd-dev", reference:"2.0.1-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"liblrmd28", reference:"2.0.1-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libpe-rules26", reference:"2.0.1-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libpe-status28", reference:"2.0.1-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libpengine-dev", reference:"2.0.1-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libpengine27", reference:"2.0.1-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libstonithd-dev", reference:"2.0.1-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libstonithd26", reference:"2.0.1-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libtransitioner25", reference:"2.0.1-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"pacemaker", reference:"2.0.1-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"pacemaker-cli-utils", reference:"2.0.1-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"pacemaker-common", reference:"2.0.1-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"pacemaker-dev", reference:"2.0.1-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"pacemaker-doc", reference:"2.0.1-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"pacemaker-remote", reference:"2.0.1-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"pacemaker-resource-agents", reference:"2.0.1-5+deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
