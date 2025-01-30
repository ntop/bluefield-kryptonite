# Kryptonite
This repository provides a test/benchmarking tool for **BlueField SuperNICs**.
This tool is implementing (PoC level) a NetFlow-like application that offloads flow 
processing to the **DPU** by leveraging on **DOCA Flow CT** and can run on an
interface pair, both in passive mode or with packet forwarding.
It can run both on the DPU (ARM cores) or on the host.

Compatible with:

- BlueField-3
- ConnectX 6/7
 
## 🚀 Features

- Implements a **NetFlow-like application** for flow processing.
- Offloads flow handling tasks to the **DPU**, reducing CPU overhead.
- Includes functionality for:
  - Flow creation
  - Flow aging
  - Flow statistics collection
- Provides benchmarks for flow insertion, flow table capacity, aging performance
- Supports integration with NVIDIA **DOCA Flow CT** APIs.

## 🛠 Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/ntop/bluefield-kryptonite.git
   cd bluefield-kryptonite

3. **Compile**

   ```
   make

4. **Run**

   > Please refer to the DOCA Flow CT documentation to configure the adapter
   > before running the tool. For the impatient, check the *Adapter Configuration*
   > section below.

   ```
   sudo ./kryptonite -- -p c7:00.0 -s

## Options

| Argument                    | Description                                                          |
|-----------------------------|----------------------------------------------------------------------|
| `-p` `--pci-addr` *addr*    | DOCA Flow CT device PCI address                                      |
| `-d` `--idle-timeout` *sec* | Maximum (seconds) flow idle lifetime (default: 60)                   |
| `-w` `--enable-fwd`         | Enable packet forwarding                                             |
| `-s` `--enable-sw-ct`       | Enable software (shadow) flow table                                  |
| `-e` `--enable-flow-export` | Print flow updates periodically (requires -s) and at flow expiration |
| `-t` `--verbose` *level*    | Trace verbosity level (0..3) (default: 1)                            |

## Adapter Configuration

Configuration instructions are available here for the impatients. The tool can run on the ARM cores
on the BlueField DPU, on the host configuring the BlueField in NIC mode, or on the host using a
ConnectX adapter. Please refer to the official documentation for further instructions.

Make sure hugepages are configured on the system

   ```bash
   echo '8192' | sudo tee -a /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
   mkdir /mnt/huge
   mount -t hugetlbfs -o pagesize=2M nodev /mnt/huge
   ```

### BlueField (DPU) Configuration

(Run on the DPU/ARM)

1. Modify */etc/default/grub*

   ```text
   GRUB_CMDLINE_LINUX="iommu.passthrough=1"

2. Update grub

   ```bash
   update-grub
   reboot

3. Run mst and list the devices

   ```bash
   mst start
   mst status -v

4. Set LAG_RESOURCE_ALLOCATION

   ```bash
   mlxconfig -d /dev/mst/mt41692_pciconf0.1 s LAG_RESOURCE_ALLOCATION=1
   mlxconfig -d /dev/mst/mt41692_pciconf0 s LAG_RESOURCE_ALLOCATION=1

5. Modify /etc/mellanox/mlnx-bf.conf

   ```text
   ALLOW_SHARED_RQ="no"

6. Configure eswitch mode

   ```bash
   devlink dev param set pci/0000:03:00.0 name esw_multiport value true cmode runtime
   devlink dev param set pci/0000:03:00.1 name esw_multiport value true cmode runtime

### BlueField (Host/NIC) Configuration

(Run on the host)

1. Run mst and list the devices

   ```bash
   mst start
   mst status -v

2. Enable NIC Mode (INTERNAL_CPU_OFFLOAD_ENGINE=1 disables the DPU):

   ```bash
   mlxconfig -d /dev/mst/mt41692_pciconf0 s \
   INTERNAL_CPU_PAGE_SUPPLIER=1 \
   INTERNAL_CPU_ESWITCH_MANAGER=1 \
   INTERNAL_CPU_IB_VPORT0=1 \
   INTERNAL_CPU_OFFLOAD_ENGINE=1 \

3. Power cycle the system

   ```bash
   shutdown now

4. Check DOCA Flow CT capabilities

   ```bash
   /opt/mellanox/doca/tools/doca_caps -p c7:00.0 | grep flow
      flow
          flow_ct                                       supported

5. Configure LAG_RESOURCE_ALLOCATION

   ```bash
   mlxconfig -d /dev/mst/mt41692_pciconf0 s LAG_RESOURCE_ALLOCATION=1

6. Configure eswitch mode

   ```bash
   devlink dev eswitch set pci/0000:c7:00.0 mode switchdev
   devlink dev param set pci/0000:c7:00.0 name esw_multiport value true cmode runtime


### ConnectX (Host/NIC) Configuration

(Run on the host)

1. Run mst and list the devices

   ```bash
   mst start
   mst status -v

2. Check DOCA Flow CT capabilities

   ```bash
   /opt/mellanox/doca/tools/doca_caps -p c7:00.0 | grep flow
      flow
          flow_ct                                       supported

3. Configure LAG_RESOURCE_ALLOCATION

   ```bash
   mlxconfig -d /dev/mst/mt41692_pciconf0 s LAG_RESOURCE_ALLOCATION=1

4. Configure eswitch mode

   ```bash
   devlink dev eswitch set pci/0000:c7:00.0 mode switchdev
   devlink dev param set pci/0000:c7:00.0 name esw_multiport value true cmode runtime

