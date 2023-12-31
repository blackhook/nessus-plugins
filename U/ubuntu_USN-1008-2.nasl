#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1008-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50301);
  script_version("1.9");
  script_cvs_date("Date: 2019/09/19 12:54:26");

  script_cve_id("CVE-2010-2237", "CVE-2010-2238", "CVE-2010-2239", "CVE-2010-2242");
  script_bugtraq_id(41981);
  script_xref(name:"USN", value:"1008-2");

  script_name(english:"Ubuntu 10.04 LTS : virtinst update (USN-1008-2)");
  script_summary(english:"Checks dpkg output for updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Ubuntu host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Libvirt in Ubuntu 10.04 LTS now no longer probes qemu disks for the
image format and defaults to 'raw' when the format is not specified in
the XML. This change in behavior breaks virt-install --import because
virtinst in Ubuntu 10.04 LTS did not allow for specifying a disk
format and does not specify a format in the XML. This update adds the
'format=' option when specifying a disk. For example, to import an
existing VM which uses a qcow2 disk format, use somthing like the
following :

virt-install --connect=qemu:///session --name test-import --ram=256 \
--disk path=<path to qcow2 image>,format=qcow2 --import

For more information, see man 1 virt-install.

It was discovered that libvirt would probe disk backing stores without
consulting the defined format for the disk. A privileged attacker in
the guest could exploit this to read arbitrary files on the host. This
issue only affected Ubuntu 10.04 LTS. By default, guests are confined
by an AppArmor profile which provided partial protection against this
flaw. (CVE-2010-2237, CVE-2010-2238)

It was discovered that libvirt would create new VMs without
setting a backing store format. A privileged attacker in the
guest could exploit this to read arbitrary files on the
host. This issue did not affect Ubuntu 8.04 LTS. In Ubuntu
9.10 and later guests are confined by an AppArmor profile
which provided partial protection against this flaw.
(CVE-2010-2239)

Jeremy Nickurak discovered that libvirt created iptables
rules with too lenient mappings of source ports. A
privileged attacker in the guest could bypass intended
restrictions to access privileged resources on the host.
(CVE-2010-2242).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1008-2/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-virtinst and / or virtinst packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-virtinst");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:virtinst");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2019 Canonical, Inc. / NASL script (C) 2010-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! preg(pattern:"^(10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"python-virtinst", pkgver:"0.500.1-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"virtinst", pkgver:"0.500.1-2ubuntu6.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-virtinst / virtinst");
}
