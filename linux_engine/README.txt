README for OCTEON Linux Crypto Engine Release v3.1.0


Table of Contents:
==================
01. What is in this release
02. Supported OCTEON_MODELs
03. Supported Operating Modes
04. Dependencies
05. Installed Directory Structure
06. Pre-requisites to Compiling the Engine
07. Building the Engine Library for OCTEON
08. Cleaning Engine Build
09. Testing Engine Using OpenSSL on OCTEON Linux
10. Speed Test
11. Supported Features
12. Additional Documentation
13. Known Issues
14. Change History



01. What is in this release
===========================
  This release contains Crypto Engine source code for OCTEON Linux.



02. Supported OCTEON_MODELs
===========================
  This release supports the following OCTEON_MODELs.
        - CN70xx
        - CN68xx
        - CN66xx
        - CN63xx
        - CN61xx



03. Supported Operating Modes
=============================
  This release supports the following Operating modes
        - Linux N64



04. Dependencies
================
  This release requires the following OCTEON SDKs:

   a) OCTEON-SDK-3.1.0-515

   b) OCTEON-LINUX-3.1.0-515

   c) SDK patch release2

  NOTE: Before compiling the sources, the environment variables need
        to be setup. Please refer SDK README.txt located at 
        /usr/local/Cavium_Networks/OCTEON-SDK/ to setup the environment
        variables.



05. Installed Directory Structure
=================================
  $OCTEON_ROOT
      |
      |--- applications/linux_engine
      |         (source files for building the Engine)



06. Pre-requisites to Compiling the Engine 
==========================================
a) Setup the OCTEON development environment.

     # cd /usr/local/Cavium_Networks/OCTEON-SDK

     # source env-setup <OCTEON_MODEL> --runtime-model
       (Please refer Section-02 for supported OCTEON_MODELS).

b) Configuration Selection

     # cd $OCTEON_ROOT/linux/embedded_rootfs
     # cp -f default.config .config

     # make menuconfig

     Select Toolchain ABI to be N64 as follows -
     Global Options  --->
        Toolchain ABI and C Library (N64 ABI with GNU C Library (glibc))  --->
                  ( ) N32 ABI with GNU C library Octeon ISA (glibc)
                  ( ) N32 ABI with GNU C library Octeon2 ISA (glibc)
                  ( ) N32 ABI with GNU C library Octeon3 ISA (glibc)
                  ( ) N64 ABI with GNU c library Octeon ISA (glibc)
                  ( ) N64 ABI with GNU c library Octeon2 ISA (glibc)
                  (X) N64 ABI with GNU c library Octeon3 ISA (glibc)
     For different Octeon version, choose ABI accordingly.
          
     Make sure the following options are enabled. These options are enabled
     by default -

        [*] openssl 
            [*] engine 

     Save this configuration and exit.

c) Building OCTEON Linux Kernel

     # cd $OCTEON_ROOT/linux
     
       If the OpenSSL Version is other than openssl-1.0.1g then 
       it is must to set the environmental variable OPENSSL_VERSION.
     
     # export OPENSSL_VERSION=x.x.xy 
              (for example: export OPENSSL_VERSION=1.0.1g)
     
     Before building OCTEON Linux kernel copy the openssl-1.0.1g.tar.gz
     in $OCTEON_ROOT/linux/embedded_rootfs/storage directory.

     openssl-1.0.1g.tar.gz can be downloaded from the following URL.

          http://www.openssl.org/source/
     
     # make kernel
       It builds vmlinux.64 image and is available at 
        $OCTEON_ROOT/linux/kernel/linux/


The below mentioned steps (d) and (e) must be executed after booting the 
vmlinux.64 image onto OCTEON.

Please refer to SDK documentation on HOWTO boot Linux on OCTEON.

Assuming SGMII QLM module connected to OCTEON Board.

d) Insert the octeon-ethernet module.
   
    # modprobe octeon-ethernet

e) Assign the IP address to one of the interface

    Ex:
    # ifconfig eth0 <IP>



07. Building the Engine Library for OCTEON
==========================================
   Compiling the Linux (step 6c) implicitly compiles the Engine for OCTEON,
   and the shared library is called "libocteon.so".

   The libocteon.so is available in the OCTEON Filesystem at
       /usr/lib64   if ABI N64 is selected



08. Cleaning Engine Build
=========================
This step is needed when OCTEON Linux Kernel is cleaned.
Linux engine build can be cleaned by the following steps.

  # cd $OCTEON_ROOT/applications/linux_engine

  # make OCTEON_TARGET=linux_64 clean     if ABI N64 is selected



09. Testing Engine Using OpenSSL on OCTEON Linux
================================================

a) Running the openssl s_server with engine

   For OCTEON-II
   -------------

   # openssl s_server -engine octeon -cert <CertificateFile> -key <KeyFile> \
     -WWW -port 4433

     The above command uses OCTEON crypto acceleration.

     Note!! The sample server key and server certificate[server.pem]
            can be found from the following location.

               /usr/lib64/octeon2/engines

   For OCTEON-III
   --------------

   # export LD_LIBRARY_PATH=/usr/lib64-fp

   # openssl s_server -engine octeon -cert <CertificateFile> -key <KeyFile> \
     -WWW -port 4433

     The above command uses OCTEON crypto acceleration.

     Note!! The sample server key and server certificate[server.pem]
            can be found from the following location.

               /usr/lib64-fp/engines

b) Run the client from x86 machine which is in the same LAN
   to connect to the s_server running on OCTEON.

   i) Connecting through openssl client
         $ openssl s_client -connect <IP>:<port>
            where 
            <IP> is IP address of OCTEON used in step 6e.
            <port> is 4433 [default port number on which s_server runs].

         Type Q to quit on s_client terminal.


   ii) Connecting through Browser

        Type the following in the address bar of your browser.
        
        https://<IP>:<port>/<file>
           where, 
             <IP> is IP address of OCTEON used in step 6e.
             <port> is 4433 [default port number on which s_server runs].
             <file> is name of the file located at working directory of 
                    s_server (OCTEON openssl s_server).

        This displays the content of the <file>.



10. Speed Test
==============
Performance of various openssl crypto algorithms through OCTEON Engine 
can be tested with the following commands.

   a. AES-128
       # openssl speed -evp aes-128-cbc -engine octeon

   b. SHA1
       # openssl speed -evp sha1 -engine octeon

   c. RSA
       # openssl speed rsa -engine octeon

   d. DSA
       # openssl speed dsa -engine octeon



11. Supported Features
======================
   a. Symmetric Algorithms
         - 3DES             : CBC
         - AES 128,192,256  : CBC, ECB, GCM
         - DES (64 bit)
         - Camellia         : CBC, ECB, OFB128, CFB128, CFB1, CFB8
   b. Digests
         - MD5
         - SHA1
         - SHA224, SHA256, SHA384, SHA512
   c. Key Exchange
         - RSA
         - DH
         - DSA



12. Additional Documentation
============================
    The additional documentation of OCTEON Linux Crypto Engine can be found 
    from the following location.

    $OCTEON_ROOT/applications/linux_engine/docs/html/index.html



13. Known Issues
================
    No known issues.



14. Change History
==================
Release 3.1
      - Ported to SDK 3.1.0
      - Upgraded to openssl-1.0.1g
      - Support added for Octeon-III boards
      - Removed Linux N32 support
      - Modularized code by splitting it into different files based on ciphers

Release 2.3
      - Ported to SDK 2.3.0
      - Added support for SHA2 algorithms
      - Sample sslserver application is deprecated in this release.

Release 2.0
      - Ported to SDK 2.0.0
      - Removed CRYPTO-CORE dependency
          
Release 0.5
      - Ported to SDK 1.7.0
      - Minor cosmetic changes done in the code.

Release 0.4
      - Added user space modexp support for parts with no issues.
      - MD5/SHA1 bug fixes.
      - Ported to SDK 1.6.0 

Release 0.3
      - Ported to SDK 1.5.0 (build 187)

Release 0.2
      - Installation directory changed.
      - Destroy engine interface implemented.

Release 0.1     
      - Initial Pre-Release


<EOF>
