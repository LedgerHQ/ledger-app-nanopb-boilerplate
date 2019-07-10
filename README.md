# Ledger nanopb app

## Overview
This repository is a boilerplate for a Nano S/X app tht would use NanoPB.
It does very little, and just expose a minimal API (get_app_config, decode_tx_from_apdu). 

## Building and installing
To build and install the app on your Ledger Nano S you must set up the Ledger Nano S build environments. Please follow the Getting Started instructions at [here](https://ledger.readthedocs.io/en/latest/userspace/getting_started.html).

If you don't want to setup a global environnment, you can also setup one just for this app by sourcing `prepare-devenv.sh` with the right target (`s` or `x`).

install prerequisite and switch to a Nano X dev-env:

```bash
sudo apt install python3-venv
# (x or s, depending on your device)
source prepare-devenv.sh x 
```

Compile and load the app onto the device:
```bash
make load
```

Refresh the repo (required after Makefile edits):
```bash
make clean
```

Remove the app from the device:
```bash
make delete
```


## Example of Ledger wallet functionality

This app writes its output on the host's terminal through the `PRINTF` macro. Instructions to setup the host are given [`here`](https://ledger.readthedocs.io/en/latest/userspace/debugging.html).

Test functionality:
```bash
# (x or s, depending on your device)
source prepare-devenv.sh x
python3 py3_tests/test_send.py
```

This script builds a transaction with dummy data, serializes it and send it to the device.
The device will then decode it and display every element it contains.
This is a very basic example, as it is limited to static memory allocation. To enable dynamyc memory allocation, you can customize the interface provided in `src/pb_custom.(c|h)` and set `PB_ENABLE_MALLOC` inside `ledger-nanopb/pb.h`. You then have to provide your own implmentation of `realloc` and `free`. For instance, you could use [`umm_malloc`](https://github.com/rhempel/umm_malloc).
Be carefull with heap and stack usage, especially on Nano S.

## Debugging
`DEBUG` is set by default [`here.`](https://github.com/LedgerHQ/ledger-app-nanopb-boilerplate/blob/master/Makefile#L85) and enables `PRINTF` ([`see here`](https://ledger.readthedocs.io/en/latest/userspace/debugging.html))
Instrumentation is available for `pb_decode` and its subcalls. To enable it, uncomment [`this line. `](https://github.com/LedgerHQ/ledger-app-nanopb-boilerplate/blob/master/Makefile#L93).

## Documentation
This follows the specification available in the [`api.asc`](https://github.com/LedgerHQ/ledger-app-nanopb/blob/master/doc/api.asc).
