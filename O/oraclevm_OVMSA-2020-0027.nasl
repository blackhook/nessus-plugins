#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2020-0027.
#
# @DEPRECATED@
#
# Disabled on 2020/07/16. Security advisory retracted by vendor.

include("compat.inc");

if (description)
{
  script_id(138415);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/17");

  script_cve_id("CVE-2017-15289", "CVE-2017-18030", "CVE-2018-12207", "CVE-2020-0543");

  script_name(english:"OracleVM 3.4 : xen (OVMSA-2020-0027) (deprecated)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - BUILDINFO: OVMF
    commit=173bf5c847e3ca8b42c11796ce048d8e2e916ff8

  - BUILDINFO: xen
    commit=077233184260bd831e7c4afdd4aebb0bced6ee32

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=6e676a4ba6bbd437a2a8dbfc3c6e591d920b013b

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - x86/vtd: Hide superpage support for SandyBridge IOMMUs
    (Andrew Cooper) [Orabug: 31366846] (CVE-2018-12207)
    (CVE-2018-12207)

  - BUILDINFO: OVMF
    commit=173bf5c847e3ca8b42c11796ce048d8e2e916ff8

  - BUILDINFO: xen
    commit=4cfb88a0f248605ca655e0609f0650c4563be653

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=6e676a4ba6bbd437a2a8dbfc3c6e591d920b013b

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - x86/spec-ctrl: Allow the RDRAND/RDSEED features to be
    hidden (Andrew Cooper) [Orabug: 31470704]
    (CVE-2020-0543) (CVE-2020-0543)

  - cirrus: handle negative pitch in
    cirrus_invalidate_region (Wolfgang Bumiller) [Orabug:
    31476272] (CVE-2017-18030)

  - cirrus: fix oob access in mode4and5 write functions
    (Gerd Hoffmann) [Orabug: 31476272] (CVE-2017-15289)

  - BUILDINFO: OVMF
    commit=173bf5c847e3ca8b42c11796ce048d8e2e916ff8

  - BUILDINFO: xen
    commit=3206f3109cfd432d6e5bbffbcc9839f5b8ed1e44

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - x86/spec-ctrl: Mitigate the Special Register Buffer Data
    Sampling sidechannel (Andrew Cooper) [Orabug: 31470704]
    (CVE-2020-0543) (CVE-2020-0543)

  - x86/spec-ctrl: CPUID/MSR definitions for Special
    Register Buffer Data Sampling (Andrew Cooper) [Orabug:
    31470704] (CVE-2020-0543) (CVE-2020-0543)

  - BUILDINFO: OVMF
    commit=173bf5c847e3ca8b42c11796ce048d8e2e916ff8

  - BUILDINFO: xen
    commit=0bef1944b340a7ec3e93a20b472effa654f5ee16

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - x86/crash: force unlock console before printing on kexec
    crash (Igor Druzhinin) [Orabug: 31255931]

  - BUILDINFO: OVMF
    commit=173bf5c847e3ca8b42c11796ce048d8e2e916ff8

  - BUILDINFO: xen
    commit=69a58ac753bd61961615f9208f8e1ee5ce946538

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - redtape: x86/tsx: TAA regressions (Patrick Colp)
    [Orabug: 31240359]

This security advisory was retracted by OracleVM on 2020/07/16."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2020-July/000990.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"n/a"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0543");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}

exit(0, "This plugin has been deprecated. The advisory involved was retracted.");
