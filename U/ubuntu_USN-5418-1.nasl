##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5418-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161060);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2021-26401",
    "CVE-2022-23036",
    "CVE-2022-23037",
    "CVE-2022-23038",
    "CVE-2022-23039",
    "CVE-2022-23040",
    "CVE-2022-23042",
    "CVE-2022-24958",
    "CVE-2022-25258",
    "CVE-2022-25375",
    "CVE-2022-26490",
    "CVE-2022-26966",
    "CVE-2022-27223"
  );
  script_xref(name:"USN", value:"5418-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS : Linux kernel vulnerabilities (USN-5418-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5418-1 advisory.

  - LFENCE/JMP (mitigation V2-2) may not sufficiently mitigate CVE-2017-5715 on some AMD CPUs.
    (CVE-2021-26401)

  - Linux PV device frontends vulnerable to attacks by backends T[his CNA information record relates to
    multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Several Linux PV
    device frontends are using the grant table interfaces for removing access rights of the backends in ways
    being subject to race conditions, resulting in potential data leaks, data corruption by malicious
    backends, and denial of service triggered by malicious backends: blkfront, netfront, scsifront and the
    gntalloc driver are testing whether a grant reference is still in use. If this is not the case, they
    assume that a following removal of the granted access will always succeed, which is not true in case the
    backend has mapped the granted page between those two operations. As a result the backend can keep access
    to the memory page of the guest no matter how the page will be used after the frontend I/O has finished.
    The xenbus driver has a similar problem, as it doesn't check the success of removing the granted access of
    a shared ring buffer. blkfront: CVE-2022-23036 netfront: CVE-2022-23037 scsifront: CVE-2022-23038
    gntalloc: CVE-2022-23039 xenbus: CVE-2022-23040 blkfront, netfront, scsifront, usbfront, dmabuf, xenbus,
    9p, kbdfront, and pvcalls are using a functionality to delay freeing a grant reference until it is no
    longer in use, but the freeing of the related data page is not synchronized with dropping the granted
    access. As a result the backend can keep access to the memory page even after it has been freed and then
    re-used for a different purpose. CVE-2022-23041 netfront will fail a BUG_ON() assertion if it fails to
    revoke access in the rx path. This will result in a Denial of Service (DoS) situation of the guest which
    can be triggered by the backend. CVE-2022-23042 (CVE-2022-23036, CVE-2022-23037, CVE-2022-23038,
    CVE-2022-23039, CVE-2022-23040, CVE-2022-23042)

  - drivers/usb/gadget/legacy/inode.c in the Linux kernel through 5.16.8 mishandles dev->buf release.
    (CVE-2022-24958)

  - An issue was discovered in drivers/usb/gadget/composite.c in the Linux kernel before 5.16.10. The USB
    Gadget subsystem lacks certain validation of interface OS descriptor requests (ones with a large array
    index and ones associated with NULL function pointer retrieval). Memory corruption might occur.
    (CVE-2022-25258)

  - An issue was discovered in drivers/usb/gadget/function/rndis.c in the Linux kernel before 5.16.10. The
    RNDIS USB gadget lacks validation of the size of the RNDIS_MSG_SET command. Attackers can obtain sensitive
    information from kernel memory. (CVE-2022-25375)

  - st21nfca_connectivity_event_received in drivers/nfc/st21nfca/se.c in the Linux kernel through 5.16.12 has
    EVT_TRANSACTION buffer overflows because of untrusted length parameters. (CVE-2022-26490)

  - An issue was discovered in the Linux kernel before 5.16.12. drivers/net/usb/sr9700.c allows attackers to
    obtain sensitive information from heap memory via crafted frame lengths from a device. (CVE-2022-26966)

  - In drivers/usb/gadget/udc/udc-xilinx.c in the Linux kernel before 5.16.12, the endpoint index is not
    validated and might be manipulated by the host for out-of-array access. (CVE-2022-27223)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5418-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27223");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-cloud-tools-4.15.0-1128");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-4.15.0-1128");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-hwe-cloud-tools-4.15.0-1128");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-hwe-tools-4.15.0-1128");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-tools-4.15.0-1128");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-4.15-cloud-tools-4.15.0-1138");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-4.15-headers-4.15.0-1138");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-4.15-tools-4.15.0-1138");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-cloud-tools-4.15.0-1138");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-headers-4.15.0-1138");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-tools-4.15.0-1138");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1042-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1093-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1114-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1122-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1127-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1128-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1138-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-177-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-177-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-177-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-1128-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-1138-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-177");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-177-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-177-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-crashdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-dell300x-headers-4.15.0-1042");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-dell300x-tools-4.15.0-1042");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-4.15-headers-4.15.0-1122");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-4.15-tools-4.15.0-1122");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-headers-4.15.0-1122");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-tools-4.15.0-1122");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1042-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1093-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1114-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1122-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1127-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1128-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1138-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-177");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-177-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-177-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-177-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-cloud-tools-4.15.0-177");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-tools-4.15.0-177");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1042-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1093-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1114-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1122-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1127-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1128-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1128-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1138-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-177-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-177-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-177-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-1042-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-1093-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-1122-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-1128-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-1138-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-177-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-177-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-headers-4.15.0-1114");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-tools-4.15.0-1114");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1042-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1093-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1114-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1122-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1127-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1128-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1138-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-177-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-177-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-177-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-1093-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-1122-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-1128-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-1138-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-177-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-headers-4.15.0-1093");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-tools-4.15.0-1093");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-snapdragon-headers-4.15.0-1127");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-snapdragon-tools-4.15.0-1127");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-4.15.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1042-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1093-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1114-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1122-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1127-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1128-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1138-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-177");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-177-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-177-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-177-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-16.04-edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('14.04' >< os_release || '16.04' >< os_release || '18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04 / 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '14.04', 'pkgname': 'linux-azure', 'pkgver': '4.15.0.1138.110'},
    {'osver': '14.04', 'pkgname': 'linux-azure-cloud-tools-4.15.0-1138', 'pkgver': '4.15.0-1138.151~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-azure-headers-4.15.0-1138', 'pkgver': '4.15.0-1138.151~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-azure-tools-4.15.0-1138', 'pkgver': '4.15.0-1138.151~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-buildinfo-4.15.0-1138-azure', 'pkgver': '4.15.0-1138.151~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-cloud-tools-4.15.0-1138-azure', 'pkgver': '4.15.0-1138.151~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-cloud-tools-azure', 'pkgver': '4.15.0.1138.110'},
    {'osver': '14.04', 'pkgname': 'linux-headers-4.15.0-1138-azure', 'pkgver': '4.15.0-1138.151~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-headers-azure', 'pkgver': '4.15.0.1138.110'},
    {'osver': '14.04', 'pkgname': 'linux-image-4.15.0-1138-azure', 'pkgver': '4.15.0-1138.151~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-image-azure', 'pkgver': '4.15.0.1138.110'},
    {'osver': '14.04', 'pkgname': 'linux-image-unsigned-4.15.0-1138-azure', 'pkgver': '4.15.0-1138.151~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-modules-4.15.0-1138-azure', 'pkgver': '4.15.0-1138.151~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-modules-extra-4.15.0-1138-azure', 'pkgver': '4.15.0-1138.151~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-modules-extra-azure', 'pkgver': '4.15.0.1138.110'},
    {'osver': '14.04', 'pkgname': 'linux-signed-azure', 'pkgver': '4.15.0.1138.110'},
    {'osver': '14.04', 'pkgname': 'linux-signed-image-azure', 'pkgver': '4.15.0.1138.110'},
    {'osver': '14.04', 'pkgname': 'linux-tools-4.15.0-1138-azure', 'pkgver': '4.15.0-1138.151~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-tools-azure', 'pkgver': '4.15.0.1138.110'},
    {'osver': '16.04', 'pkgname': 'linux-aws-edge', 'pkgver': '4.15.0.1128.118'},
    {'osver': '16.04', 'pkgname': 'linux-aws-headers-4.15.0-1128', 'pkgver': '4.15.0-1128.137~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-aws-hwe', 'pkgver': '4.15.0.1128.118'},
    {'osver': '16.04', 'pkgname': 'linux-aws-hwe-cloud-tools-4.15.0-1128', 'pkgver': '4.15.0-1128.137~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-aws-hwe-tools-4.15.0-1128', 'pkgver': '4.15.0-1128.137~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-azure', 'pkgver': '4.15.0.1138.128'},
    {'osver': '16.04', 'pkgname': 'linux-azure-cloud-tools-4.15.0-1138', 'pkgver': '4.15.0-1138.151~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-azure-edge', 'pkgver': '4.15.0.1138.128'},
    {'osver': '16.04', 'pkgname': 'linux-azure-headers-4.15.0-1138', 'pkgver': '4.15.0-1138.151~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-azure-tools-4.15.0-1138', 'pkgver': '4.15.0-1138.151~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-1093-oracle', 'pkgver': '4.15.0-1093.102~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-1122-gcp', 'pkgver': '4.15.0-1122.136~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-1128-aws', 'pkgver': '4.15.0-1128.137~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-1138-azure', 'pkgver': '4.15.0-1138.151~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-177-generic', 'pkgver': '4.15.0-177.186~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-177-lowlatency', 'pkgver': '4.15.0-177.186~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.15.0-1128-aws', 'pkgver': '4.15.0-1128.137~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.15.0-1138-azure', 'pkgver': '4.15.0-1138.151~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.15.0-177-generic', 'pkgver': '4.15.0-177.186~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.15.0-177-lowlatency', 'pkgver': '4.15.0-177.186~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-azure', 'pkgver': '4.15.0.1138.128'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-azure-edge', 'pkgver': '4.15.0.1138.128'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-hwe-16.04', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-hwe-16.04-edge', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-16.04', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-16.04', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-gcp', 'pkgver': '4.15.0.1122.123'},
    {'osver': '16.04', 'pkgname': 'linux-gcp-headers-4.15.0-1122', 'pkgver': '4.15.0-1122.136~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-gcp-tools-4.15.0-1122', 'pkgver': '4.15.0-1122.136~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-generic-hwe-16.04', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-generic-hwe-16.04-edge', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-gke', 'pkgver': '4.15.0.1122.123'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-1093-oracle', 'pkgver': '4.15.0-1093.102~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-1122-gcp', 'pkgver': '4.15.0-1122.136~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-1128-aws', 'pkgver': '4.15.0-1128.137~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-1138-azure', 'pkgver': '4.15.0-1138.151~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-177', 'pkgver': '4.15.0-177.186~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-177-generic', 'pkgver': '4.15.0-177.186~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-177-lowlatency', 'pkgver': '4.15.0-177.186~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-aws-hwe', 'pkgver': '4.15.0.1128.118'},
    {'osver': '16.04', 'pkgname': 'linux-headers-azure', 'pkgver': '4.15.0.1138.128'},
    {'osver': '16.04', 'pkgname': 'linux-headers-azure-edge', 'pkgver': '4.15.0.1138.128'},
    {'osver': '16.04', 'pkgname': 'linux-headers-gcp', 'pkgver': '4.15.0.1122.123'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-hwe-16.04', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-hwe-16.04-edge', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-headers-gke', 'pkgver': '4.15.0.1122.123'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-hwe-16.04', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-headers-oem', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-headers-oracle', 'pkgver': '4.15.0.1093.81'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-hwe-16.04', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-hwe-cloud-tools-4.15.0-177', 'pkgver': '4.15.0-177.186~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-hwe-tools-4.15.0-177', 'pkgver': '4.15.0-177.186~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1093-oracle', 'pkgver': '4.15.0-1093.102~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1122-gcp', 'pkgver': '4.15.0-1122.136~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1128-aws-hwe', 'pkgver': '4.15.0-1128.137~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1138-azure', 'pkgver': '4.15.0-1138.151~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-177-generic', 'pkgver': '4.15.0-177.186~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-177-lowlatency', 'pkgver': '4.15.0-177.186~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-aws-hwe', 'pkgver': '4.15.0.1128.118'},
    {'osver': '16.04', 'pkgname': 'linux-image-azure', 'pkgver': '4.15.0.1138.128'},
    {'osver': '16.04', 'pkgname': 'linux-image-azure-edge', 'pkgver': '4.15.0.1138.128'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-hwe-16.04', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-image-gcp', 'pkgver': '4.15.0.1122.123'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-hwe-16.04', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-image-gke', 'pkgver': '4.15.0.1122.123'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-image-oem', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-image-oracle', 'pkgver': '4.15.0.1093.81'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-1093-oracle', 'pkgver': '4.15.0-1093.102~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-1122-gcp', 'pkgver': '4.15.0-1122.136~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-1128-aws', 'pkgver': '4.15.0-1128.137~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-1138-azure', 'pkgver': '4.15.0-1138.151~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-177-generic', 'pkgver': '4.15.0-177.186~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-177-lowlatency', 'pkgver': '4.15.0-177.186~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-hwe-16.04', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-hwe-16.04', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-1093-oracle', 'pkgver': '4.15.0-1093.102~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-1122-gcp', 'pkgver': '4.15.0-1122.136~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-1128-aws', 'pkgver': '4.15.0-1128.137~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-1138-azure', 'pkgver': '4.15.0-1138.151~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-177-generic', 'pkgver': '4.15.0-177.186~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-177-lowlatency', 'pkgver': '4.15.0-177.186~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.15.0-1093-oracle', 'pkgver': '4.15.0-1093.102~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.15.0-1122-gcp', 'pkgver': '4.15.0-1122.136~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.15.0-1128-aws', 'pkgver': '4.15.0-1128.137~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.15.0-1138-azure', 'pkgver': '4.15.0-1138.151~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.15.0-177-generic', 'pkgver': '4.15.0-177.186~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-aws-hwe', 'pkgver': '4.15.0.1128.118'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-azure', 'pkgver': '4.15.0.1138.128'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-azure-edge', 'pkgver': '4.15.0.1138.128'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-gcp', 'pkgver': '4.15.0.1122.123'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-gke', 'pkgver': '4.15.0.1122.123'},
    {'osver': '16.04', 'pkgname': 'linux-oem', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-oracle', 'pkgver': '4.15.0.1093.81'},
    {'osver': '16.04', 'pkgname': 'linux-oracle-headers-4.15.0-1093', 'pkgver': '4.15.0-1093.102~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-oracle-tools-4.15.0-1093', 'pkgver': '4.15.0-1093.102~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-signed-azure', 'pkgver': '4.15.0.1138.128'},
    {'osver': '16.04', 'pkgname': 'linux-signed-azure-edge', 'pkgver': '4.15.0.1138.128'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-hwe-16.04', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-hwe-16.04-edge', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-azure', 'pkgver': '4.15.0.1138.128'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-azure-edge', 'pkgver': '4.15.0.1138.128'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-hwe-16.04', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-oem', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-oracle', 'pkgver': '4.15.0.1093.81'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency-hwe-16.04', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-signed-oem', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-signed-oracle', 'pkgver': '4.15.0.1093.81'},
    {'osver': '16.04', 'pkgname': 'linux-source-4.15.0', 'pkgver': '4.15.0-177.186~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-1093-oracle', 'pkgver': '4.15.0-1093.102~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-1122-gcp', 'pkgver': '4.15.0-1122.136~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-1128-aws', 'pkgver': '4.15.0-1128.137~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-1138-azure', 'pkgver': '4.15.0-1138.151~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-177-generic', 'pkgver': '4.15.0-177.186~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-177-lowlatency', 'pkgver': '4.15.0-177.186~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-aws-hwe', 'pkgver': '4.15.0.1128.118'},
    {'osver': '16.04', 'pkgname': 'linux-tools-azure', 'pkgver': '4.15.0.1138.128'},
    {'osver': '16.04', 'pkgname': 'linux-tools-azure-edge', 'pkgver': '4.15.0.1138.128'},
    {'osver': '16.04', 'pkgname': 'linux-tools-gcp', 'pkgver': '4.15.0.1122.123'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-hwe-16.04', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-hwe-16.04-edge', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-tools-gke', 'pkgver': '4.15.0.1122.123'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-hwe-16.04', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-tools-oem', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-tools-oracle', 'pkgver': '4.15.0.1093.81'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-hwe-16.04', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-hwe-16.04', 'pkgver': '4.15.0.177.169'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.177.169'},
    {'osver': '18.04', 'pkgname': 'linux-aws-cloud-tools-4.15.0-1128', 'pkgver': '4.15.0-1128.137'},
    {'osver': '18.04', 'pkgname': 'linux-aws-headers-4.15.0-1128', 'pkgver': '4.15.0-1128.137'},
    {'osver': '18.04', 'pkgname': 'linux-aws-lts-18.04', 'pkgver': '4.15.0.1128.131'},
    {'osver': '18.04', 'pkgname': 'linux-aws-tools-4.15.0-1128', 'pkgver': '4.15.0-1128.137'},
    {'osver': '18.04', 'pkgname': 'linux-azure-4.15-cloud-tools-4.15.0-1138', 'pkgver': '4.15.0-1138.151'},
    {'osver': '18.04', 'pkgname': 'linux-azure-4.15-headers-4.15.0-1138', 'pkgver': '4.15.0-1138.151'},
    {'osver': '18.04', 'pkgname': 'linux-azure-4.15-tools-4.15.0-1138', 'pkgver': '4.15.0-1138.151'},
    {'osver': '18.04', 'pkgname': 'linux-azure-lts-18.04', 'pkgver': '4.15.0.1138.111'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1042-dell300x', 'pkgver': '4.15.0-1042.47'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1093-oracle', 'pkgver': '4.15.0-1093.102'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1114-kvm', 'pkgver': '4.15.0-1114.117'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1122-gcp', 'pkgver': '4.15.0-1122.136'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1127-snapdragon', 'pkgver': '4.15.0-1127.136'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1128-aws', 'pkgver': '4.15.0-1128.137'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1138-azure', 'pkgver': '4.15.0-1138.151'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-177-generic', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-177-generic-lpae', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-177-lowlatency', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-1128-aws', 'pkgver': '4.15.0-1128.137'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-1138-azure', 'pkgver': '4.15.0-1138.151'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-177', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-177-generic', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-177-lowlatency', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-azure-lts-18.04', 'pkgver': '4.15.0.1138.111'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-common', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic-hwe-16.04', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic-hwe-16.04-edge', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-16.04', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-16.04', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-crashdump', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-dell300x', 'pkgver': '4.15.0.1042.44'},
    {'osver': '18.04', 'pkgname': 'linux-dell300x-headers-4.15.0-1042', 'pkgver': '4.15.0-1042.47'},
    {'osver': '18.04', 'pkgname': 'linux-dell300x-tools-4.15.0-1042', 'pkgver': '4.15.0-1042.47'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-4.15-headers-4.15.0-1122', 'pkgver': '4.15.0-1122.136'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-4.15-tools-4.15.0-1122', 'pkgver': '4.15.0-1122.136'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-lts-18.04', 'pkgver': '4.15.0.1122.141'},
    {'osver': '18.04', 'pkgname': 'linux-generic', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-generic-hwe-16.04', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-generic-hwe-16.04-edge', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1042-dell300x', 'pkgver': '4.15.0-1042.47'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1093-oracle', 'pkgver': '4.15.0-1093.102'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1114-kvm', 'pkgver': '4.15.0-1114.117'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1122-gcp', 'pkgver': '4.15.0-1122.136'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1127-snapdragon', 'pkgver': '4.15.0-1127.136'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1128-aws', 'pkgver': '4.15.0-1128.137'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1138-azure', 'pkgver': '4.15.0-1138.151'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-177', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-177-generic', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-177-generic-lpae', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-177-lowlatency', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-headers-aws-lts-18.04', 'pkgver': '4.15.0.1128.131'},
    {'osver': '18.04', 'pkgname': 'linux-headers-azure-lts-18.04', 'pkgver': '4.15.0.1138.111'},
    {'osver': '18.04', 'pkgname': 'linux-headers-dell300x', 'pkgver': '4.15.0.1042.44'},
    {'osver': '18.04', 'pkgname': 'linux-headers-gcp-lts-18.04', 'pkgver': '4.15.0.1122.141'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-hwe-16.04', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-hwe-16.04-edge', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-headers-kvm', 'pkgver': '4.15.0.1114.110'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency-hwe-16.04', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oracle-lts-18.04', 'pkgver': '4.15.0.1093.103'},
    {'osver': '18.04', 'pkgname': 'linux-headers-snapdragon', 'pkgver': '4.15.0.1127.130'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual-hwe-16.04', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1042-dell300x', 'pkgver': '4.15.0-1042.47'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1093-oracle', 'pkgver': '4.15.0-1093.102'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1114-kvm', 'pkgver': '4.15.0-1114.117'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1122-gcp', 'pkgver': '4.15.0-1122.136'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1127-snapdragon', 'pkgver': '4.15.0-1127.136'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1128-aws', 'pkgver': '4.15.0-1128.137'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1138-azure', 'pkgver': '4.15.0-1138.151'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-177-generic', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-177-generic-lpae', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-177-lowlatency', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-image-aws-lts-18.04', 'pkgver': '4.15.0.1128.131'},
    {'osver': '18.04', 'pkgname': 'linux-image-azure-lts-18.04', 'pkgver': '4.15.0.1138.111'},
    {'osver': '18.04', 'pkgname': 'linux-image-dell300x', 'pkgver': '4.15.0.1042.44'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual-hwe-16.04', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-image-gcp-lts-18.04', 'pkgver': '4.15.0.1122.141'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-16.04', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-image-kvm', 'pkgver': '4.15.0.1114.110'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle-lts-18.04', 'pkgver': '4.15.0.1093.103'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon', 'pkgver': '4.15.0.1127.130'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-1042-dell300x', 'pkgver': '4.15.0-1042.47'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-1093-oracle', 'pkgver': '4.15.0-1093.102'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-1122-gcp', 'pkgver': '4.15.0-1122.136'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-1128-aws', 'pkgver': '4.15.0-1128.137'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-1138-azure', 'pkgver': '4.15.0-1138.151'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-177-generic', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-177-lowlatency', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-16.04', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-kvm', 'pkgver': '4.15.0.1114.110'},
    {'osver': '18.04', 'pkgname': 'linux-kvm-headers-4.15.0-1114', 'pkgver': '4.15.0-1114.117'},
    {'osver': '18.04', 'pkgname': 'linux-kvm-tools-4.15.0-1114', 'pkgver': '4.15.0-1114.117'},
    {'osver': '18.04', 'pkgname': 'linux-libc-dev', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency-hwe-16.04', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1042-dell300x', 'pkgver': '4.15.0-1042.47'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1093-oracle', 'pkgver': '4.15.0-1093.102'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1114-kvm', 'pkgver': '4.15.0-1114.117'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1122-gcp', 'pkgver': '4.15.0-1122.136'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1127-snapdragon', 'pkgver': '4.15.0-1127.136'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1128-aws', 'pkgver': '4.15.0-1128.137'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1138-azure', 'pkgver': '4.15.0-1138.151'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-177-generic', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-177-generic-lpae', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-177-lowlatency', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-4.15.0-1093-oracle', 'pkgver': '4.15.0-1093.102'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-4.15.0-1122-gcp', 'pkgver': '4.15.0-1122.136'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-4.15.0-1128-aws', 'pkgver': '4.15.0-1128.137'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-4.15.0-1138-azure', 'pkgver': '4.15.0-1138.151'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-4.15.0-177-generic', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-aws-lts-18.04', 'pkgver': '4.15.0.1128.131'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-azure-lts-18.04', 'pkgver': '4.15.0.1138.111'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-gcp-lts-18.04', 'pkgver': '4.15.0.1122.141'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-headers-4.15.0-1093', 'pkgver': '4.15.0-1093.102'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-lts-18.04', 'pkgver': '4.15.0.1093.103'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-tools-4.15.0-1093', 'pkgver': '4.15.0-1093.102'},
    {'osver': '18.04', 'pkgname': 'linux-signed-azure-lts-18.04', 'pkgver': '4.15.0.1138.111'},
    {'osver': '18.04', 'pkgname': 'linux-signed-generic', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-signed-generic-hwe-16.04', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-signed-generic-hwe-16.04-edge', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-azure-lts-18.04', 'pkgver': '4.15.0.1138.111'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-generic', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-generic-hwe-16.04', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-lowlatency', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-oracle-lts-18.04', 'pkgver': '4.15.0.1093.103'},
    {'osver': '18.04', 'pkgname': 'linux-signed-lowlatency', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-signed-lowlatency-hwe-16.04', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-signed-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-signed-oracle-lts-18.04', 'pkgver': '4.15.0.1093.103'},
    {'osver': '18.04', 'pkgname': 'linux-snapdragon', 'pkgver': '4.15.0.1127.130'},
    {'osver': '18.04', 'pkgname': 'linux-snapdragon-headers-4.15.0-1127', 'pkgver': '4.15.0-1127.136'},
    {'osver': '18.04', 'pkgname': 'linux-snapdragon-tools-4.15.0-1127', 'pkgver': '4.15.0-1127.136'},
    {'osver': '18.04', 'pkgname': 'linux-source', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-source-4.15.0', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1042-dell300x', 'pkgver': '4.15.0-1042.47'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1093-oracle', 'pkgver': '4.15.0-1093.102'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1114-kvm', 'pkgver': '4.15.0-1114.117'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1122-gcp', 'pkgver': '4.15.0-1122.136'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1127-snapdragon', 'pkgver': '4.15.0-1127.136'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1128-aws', 'pkgver': '4.15.0-1128.137'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1138-azure', 'pkgver': '4.15.0-1138.151'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-177', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-177-generic', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-177-generic-lpae', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-177-lowlatency', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-tools-aws-lts-18.04', 'pkgver': '4.15.0.1128.131'},
    {'osver': '18.04', 'pkgname': 'linux-tools-azure-lts-18.04', 'pkgver': '4.15.0.1138.111'},
    {'osver': '18.04', 'pkgname': 'linux-tools-common', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-tools-dell300x', 'pkgver': '4.15.0.1042.44'},
    {'osver': '18.04', 'pkgname': 'linux-tools-gcp-lts-18.04', 'pkgver': '4.15.0.1122.141'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-hwe-16.04', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-hwe-16.04-edge', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-tools-host', 'pkgver': '4.15.0-177.186'},
    {'osver': '18.04', 'pkgname': 'linux-tools-kvm', 'pkgver': '4.15.0.1114.110'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency-hwe-16.04', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oracle-lts-18.04', 'pkgver': '4.15.0.1093.103'},
    {'osver': '18.04', 'pkgname': 'linux-tools-snapdragon', 'pkgver': '4.15.0.1127.130'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual-hwe-16.04', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-virtual', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-virtual-hwe-16.04', 'pkgver': '4.15.0.177.166'},
    {'osver': '18.04', 'pkgname': 'linux-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.177.166'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

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
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-aws-cloud-tools-4.15.0-1128 / linux-aws-edge / etc');
}
