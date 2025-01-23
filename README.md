# Kryptonite
This repository provides a test/benchmarking tool for **BlueField SuperNICs**.
This tool is implementing (PoC level) a NetFlow-like application that offloads flow 
processing to the **DPU** by leveraging on **DOCA Flow CT**.
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
   cd bluefield-kryptonite.git

2. **Compile**

   ```
   make

3. **Run**
   > Please refer to the DOCA Flow CT documentation to configure the adapter
   > before running the tool.

   ```
   sudo ./kryptonite -- -p c7:00.0

## Options

| Argument                    | Description                                                          |
|-----------------------------|----------------------------------------------------------------------|
| `-p` `--pci-addr`           | DOCA Flow CT device PCI address                                      |
| `-d` `--idle-timeout`       | Maximum (seconds) flow idle lifetime (default: 60)                   |
| `-w` `--enable-fwd`         | Enable packet forwarding                                             |
| `-s` `--enable-sw-ct`       | Enable software (shadow) flow table                                  |
| `-e` `--enable-flow-export` | Print flow updates periodically (requires -s) and at flow expiration |
| `-t` `--verbose`            | Trace verbosity level (0..3) (default: 1)                            |
