#!/bin/bash

# File Name  : ESXi_7.0_VCF_Prep.ps1 
# Author     : coslush
# Version    : 0.1
# License    : Apache-2.0

bundleDLDir="/nfs/vmware/vcf/nfs-mount/offline-bundles/4.4.0.0"
for bundle in $(ls -1 $bundleDLDir/manifests/*.manifest); do 
              bundleID=`echo $bundle | awk -F/ '{ print $9 }' | awk -F. '{ print $1 }'`; 
              targetChecksum=`grep bundleChecksum $bundle | awk -F\" '{ print $4 }'`; 
              fileChecksum=`sha256sum $bundleDLDir/bundles/$bundleID.tar | awk '{ print $1 }'`;
              if [[ "$targetChecksum" == "$fileChecksum" ]]; then result="MATCH"; else result="INVALID"; fi
              echo "$bundleID $targetChecksum $fileChecksum $result"; 
done
# END SCRIPT #
